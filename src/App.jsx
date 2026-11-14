import { useCallback, useEffect, useRef, useState } from "react";
import { Capacitor } from "@capacitor/core";
import { App as CapacitorApp } from "@capacitor/app";
import { Browser } from "@capacitor/browser";
import { ShieldCheck } from "lucide-react";
import {
  verifyDestination,
  authorizeVerifiedRedirect,
  getLocalBlockVault,
  removeLocalBlockVaultEntry,
  clearLocalBlockVault
} from "./security/verificationService";
import { ScannerPanel } from "./components/ScannerPanel";
import { VerdictPanel } from "./components/VerdictPanel";
import { DeviceVaultPanel } from "./components/DeviceVaultPanel";

const isNative = Capacitor.isNativePlatform();

function createRequestId() {
  const randomPart = globalThis.crypto?.randomUUID?.()
    ?.replaceAll("-", "")
    .slice(0, 8);

  return `SG-${Date.now().toString(36).toUpperCase()}-${(
    randomPart || Math.random().toString(36).slice(2, 10)
  ).toUpperCase()}`;
}

function getRequestId(result, fallback) {
  const candidates = [
    result?.requestId,
    result?.request_id,
    result?.meta?.requestId,
    result?.metadata?.requestId
  ];

  return (
    candidates.find(
      (value) => typeof value === "string" && value.trim().length > 0
    ) || fallback
  );
}

function classifyResult(result) {
  const finalDecision = String(
    result?.finalDecision || result?.decision || ""
  ).toUpperCase();

  if (finalDecision === "BLOCK" || finalDecision === "BLOCKED") {
    return "blocked";
  }

  if (finalDecision === "SUSPICIOUS") {
    return "suspicious";
  }

  if (
    finalDecision === "KNOWN_SAFE" ||
    finalDecision === "SAFE" ||
    finalDecision === "ALLOW" ||
    finalDecision === "NO_KNOWN_THREAT"
  ) {
    return "safe";
  }

  if (
    finalDecision === "HOLD" ||
    finalDecision === "ERROR" ||
    result?.verificationStatus === "INCOMPLETE"
  ) {
    return "hold";
  }

  return "hold";
}

function validateHttpUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    return (
      ["http:", "https:"].includes(parsed.protocol) &&
      !parsed.username &&
      !parsed.password
    );
  } catch {
    return false;
  }
}

export function App() {
  const [phase, setPhase] = useState("ready");
  const [requestId, setRequestId] = useState("");
  const [result, setResult] = useState(null);
  const [isBusy, setIsBusy] = useState(false);
  const [isAuthorizing, setIsAuthorizing] = useState(false);
  const [authError, setAuthError] = useState("");
  const [inputError, setInputError] = useState("");
  const [vaultItems, setVaultItems] = useState([]);

  const destinationRef = useRef("");
  const processingRef = useRef(false);
  const lastUrlRef = useRef("");
  const lastReceivedAtRef = useRef(0);
  const mountedRef = useRef(true);

  const refreshVault = useCallback(async () => {
    try {
      const items = await getLocalBlockVault();
      if (mountedRef.current && Array.isArray(items)) {
        setVaultItems(items);
      }
    } catch {
      // Storage may be unavailable in restricted contexts
    }
  }, []);

  const handleOpenDestination = useCallback(async (userConfirmedWarning) => {
    const url = destinationRef.current;
    if (!url || !validateHttpUrl(url)) {
      setPhase("invalid");
      return;
    }

    const token = result?.verificationToken;
    setIsAuthorizing(true);
    setAuthError("");

    try {
      if (token) {
        const auth = await authorizeVerifiedRedirect({
          url,
          verificationToken: token,
          userConfirmedWarning
        });

        if (!auth?.authorized) {
          if (mountedRef.current) {
            setAuthError(
              auth?.reasonCode === "VERIFICATION_TOKEN_ALREADY_CONSUMED"
                ? "This one-time verification token was already used. Re-scan the link to open again."
                : `Redirect authorization rejected (${auth?.reasonCode || "UNVERIFIED"}).`
            );
          }
          return;
        }
      }

      if (isNative) {
        await Browser.open({ url, toolbarColor: "#090b10" });
      } else {
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.target = "_blank";
        anchor.rel = "noopener noreferrer";
        anchor.click();
      }
    } catch {
      if (mountedRef.current) {
        setAuthError("Could not launch external browser cleanly.");
      }
    } finally {
      if (mountedRef.current) {
        setIsAuthorizing(false);
      }
    }
  }, [result]);

  const handleIncomingUrl = useCallback(async (rawUrl) => {
    const url = String(rawUrl || "").trim();
    if (!url || processingRef.current) return;

    setInputError("");
    setAuthError("");

    if (!validateHttpUrl(url)) {
      setInputError("Please enter a valid HTTP or HTTPS link without embedded username/password credentials.");
      setResult(null);
      setRequestId(createRequestId());
      setPhase("invalid");
      return;
    }

    const now = Date.now();
    if (url === lastUrlRef.current && now - lastReceivedAtRef.current < 800) {
      return;
    }
    lastUrlRef.current = url;
    lastReceivedAtRef.current = now;

    const localRequestId = createRequestId();
    destinationRef.current = url;
    setRequestId(localRequestId);
    setResult(null);

    processingRef.current = true;
    setIsBusy(true);
    setPhase("checking");

    try {
      const verification = await verifyDestination(url);
      if (!mountedRef.current) return;

      setResult(verification);
      setRequestId(getRequestId(verification, localRequestId));

      const outcome = classifyResult(verification);
      setPhase(outcome);

      await refreshVault();

      if (outcome === "safe" && isNative) {
        setPhase("opening");
        await new Promise((resolve) => window.setTimeout(resolve, 450));
        if (!mountedRef.current) return;
        await Browser.open({ url, toolbarColor: "#090b10" });
        if (mountedRef.current) {
          setPhase("safe");
        }
      }
    } catch {
      if (mountedRef.current) {
        setPhase("hold");
      }
    } finally {
      processingRef.current = false;
      if (mountedRef.current) {
        setIsBusy(false);
      }
    }
  }, [refreshVault]);

  useEffect(() => {
    mountedRef.current = true;
    getLocalBlockVault()
      .then((items) => {
        if (mountedRef.current && Array.isArray(items)) {
          setVaultItems(items);
        }
      })
      .catch(() => {});

    const handleWindowEvent = (event) => {
      const detail = event?.detail;
      const url =
        typeof detail === "string"
          ? detail
          : detail?.url || detail?.data?.url;
      if (url) handleIncomingUrl(url);
    };

    window.addEventListener("safegate:incoming-url", handleWindowEvent);

    let appUrlListener;
    if (isNative) {
      CapacitorApp.addListener("appUrlOpen", (event) => {
        if (event?.url) handleIncomingUrl(event.url);
      }).then((listener) => {
        appUrlListener = listener;
        if (!mountedRef.current) listener.remove();
      });

      CapacitorApp.getLaunchUrl()
        .then((launch) => {
          if (launch?.url && mountedRef.current) {
            handleIncomingUrl(launch.url);
          }
        })
        .catch(() => {});
    }

    return () => {
      mountedRef.current = false;
      window.removeEventListener("safegate:incoming-url", handleWindowEvent);
      appUrlListener?.remove();
    };
  }, [handleIncomingUrl, refreshVault]);

  const resetScreen = () => {
    if (processingRef.current) return;
    destinationRef.current = "";
    lastUrlRef.current = "";
    setRequestId("");
    setResult(null);
    setAuthError("");
    setInputError("");
    setPhase("ready");
  };

  const handleRemoveVaultEntry = async (fingerprint) => {
    await removeLocalBlockVaultEntry(fingerprint).catch(() => {});
    await refreshVault();
  };

  const handleClearVault = async () => {
    await clearLocalBlockVault().catch(() => {});
    await refreshVault();
  };

  return (
    <div className="min-h-screen text-slate-100">
      <header className="sticky top-0 z-30 border-b border-white/10 bg-[#090b10]/90 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-400">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </div>
            <div>
              <span className="block text-sm font-extrabold tracking-wider text-white">
                SAFEGATE
              </span>
              <span className="block text-[11px] font-medium text-slate-400">
                On-Device URL Guard
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs text-slate-300">
            <span className="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5">
              {isNative ? "ANDROID GUARD" : "30-LAYER ENGINE"}
            </span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 lg:items-start">
          <section className="rounded-2xl border border-white/10 bg-[#12161f] p-5 shadow-xl sm:p-7 lg:col-span-7">
            {phase === "ready" ? (
              <ScannerPanel
                onScanUrl={handleIncomingUrl}
                isBusy={isBusy}
                inputError={inputError}
              />
            ) : (
              <VerdictPanel
                phase={phase}
                result={result}
                requestId={requestId}
                authError={authError}
                isAuthorizing={isAuthorizing}
                onReset={resetScreen}
                onAuthorizeAndOpen={handleOpenDestination}
              />
            )}
          </section>

          <div className="lg:col-span-5">
            <DeviceVaultPanel
              vaultItems={vaultItems}
              isNative={isNative}
              onRemoveEntry={handleRemoveVaultEntry}
              onClearVault={handleClearVault}
            />
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
