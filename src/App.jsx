import { useCallback, useEffect, useRef, useState } from "react";
import { Capacitor } from "@capacitor/core";
import { App as CapacitorApp } from "@capacitor/app";
import { Browser } from "@capacitor/browser";
import {
  ShieldCheck,
  ShieldBan,
  AlertTriangle,
  PauseCircle,
  Loader2,
  Copy,
  Check
} from "lucide-react";
import { verifyDestination } from "./security/verificationService";

const isNative = Capacitor.isNativePlatform();

function createFallbackRequestId() {
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

function RequestIdBadge({ value }) {
  const [copied, setCopied] = useState(false);

  if (!value) return null;

  const copyRequestId = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="flex w-full items-center justify-between gap-3 rounded-xl border border-white/10 bg-[#0b0e14] px-4 py-3 text-left">
      <div className="min-w-0">
        <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
          Request ID
        </div>
        <div
          data-testid="request-id-value"
          className="mt-1 truncate font-mono text-xs text-slate-200"
        >
          {value}
        </div>
      </div>

      <button
        type="button"
        onClick={copyRequestId}
        aria-label="Copy request ID"
        className="flex h-10 w-10 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-white/10 bg-white/5 text-slate-300 transition hover:bg-white/10 hover:text-white"
      >
        {copied ? (
          <Check className="h-4 w-4 text-emerald-400" aria-hidden="true" />
        ) : (
          <Copy className="h-4 w-4" aria-hidden="true" />
        )}
      </button>
    </div>
  );
}

export function App() {
  const [phase, setPhase] = useState("ready");
  const [requestId, setRequestId] = useState("");
  const [headline, setHeadline] = useState("");

  const destinationRef = useRef("");
  const processingRef = useRef(false);
  const lastUrlRef = useRef("");
  const lastReceivedAtRef = useRef(0);
  const mountedRef = useRef(true);

  const openDestinationDirectly = useCallback(async (targetUrl) => {
    const url = targetUrl || destinationRef.current;
    if (!url || !validateHttpUrl(url)) {
      if (mountedRef.current) setPhase("invalid");
      return;
    }

    try {
      if (isNative) {
        await Browser.open({
          url,
          toolbarColor: "#090b10"
        });
      } else {
        window.location.assign(url);
      }
    } catch {
      if (mountedRef.current) {
        setPhase("hold");
      }
    }
  }, []);

  const handleIncomingUrl = useCallback(
    async (rawUrl) => {
      const url = String(rawUrl || "").trim();
      if (!url || processingRef.current) return;

      const now = Date.now();
      if (url === lastUrlRef.current && now - lastReceivedAtRef.current < 1000) {
        return;
      }

      lastUrlRef.current = url;
      lastReceivedAtRef.current = now;

      const localId = createFallbackRequestId();
      destinationRef.current = url;
      setRequestId(localId);
      setHeadline("");

      if (!validateHttpUrl(url)) {
        setPhase("invalid");
        return;
      }

      processingRef.current = true;
      setPhase("checking");

      try {
        const result = await verifyDestination(url);
        if (!mountedRef.current) return;

        setRequestId(getRequestId(result, localId));
        setHeadline(result?.riskSummary?.headline || "");

        const outcome = classifyResult(result);

        if (outcome === "safe") {
          setPhase("opening");
          await openDestinationDirectly(url);
          if (mountedRef.current) {
            setPhase("safe");
          }
          return;
        }

        setPhase(outcome);
      } catch {
        if (mountedRef.current) {
          setPhase("hold");
        }
      } finally {
        processingRef.current = false;
      }
    },
    [openDestinationDirectly]
  );

  useEffect(() => {
    mountedRef.current = true;

    const handleWindowEvent = (event) => {
      const detail = event?.detail;
      const url =
        typeof detail === "string"
          ? detail
          : detail?.url || detail?.data?.url;
      if (url) {
        handleIncomingUrl(url);
      }
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
    } else {
      const queryUrl = new URLSearchParams(window.location.search).get("url");
      if (queryUrl) {
        queueMicrotask(() => {
          if (mountedRef.current) {
            handleIncomingUrl(queryUrl);
          }
        });
      }
    }

    return () => {
      mountedRef.current = false;
      window.removeEventListener("safegate:incoming-url", handleWindowEvent);
      appUrlListener?.remove();
    };
  }, [handleIncomingUrl]);

  const resetToReady = () => {
    if (processingRef.current) return;
    destinationRef.current = "";
    lastUrlRef.current = "";
    setRequestId("");
    setHeadline("");
    setPhase("ready");
  };

  return (
    <div className="flex min-h-screen flex-col text-slate-100">
      <header className="border-b border-white/10 bg-[#090b10]/90">
        <div className="mx-auto flex h-16 max-w-2xl items-center justify-between px-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-400">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </div>
            <span className="text-sm font-extrabold tracking-widest text-white">
              SAFEGATE
            </span>
          </div>

          <span className="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-[11px] font-semibold text-slate-300">
            ON-DEVICE
          </span>
        </div>
      </header>

      <main className="flex flex-1 items-center justify-center px-4 py-8">
        <section
          className="w-full max-w-md rounded-2xl border border-white/10 bg-[#12161f] p-6 text-center shadow-2xl sm:p-8"
          aria-live="polite"
        >
          {phase === "ready" && (
            <div className="flex flex-col items-center gap-5 py-4">
              <div className="flex h-20 w-20 items-center justify-center rounded-2xl border border-emerald-500/35 bg-emerald-500/10 text-emerald-400">
                <ShieldCheck className="h-10 w-10" aria-hidden="true" />
              </div>
              <div className="space-y-2">
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  SafeGate Ready
                </h1>
                <p className="text-sm leading-relaxed text-slate-400">
                  Link protection is active. Any clicked link is verified automatically on your device before opening.
                </p>
              </div>
            </div>
          )}

          {(phase === "checking" || phase === "opening") && (
            <div className="flex flex-col items-center gap-5 py-4">
              <div className="flex h-20 w-20 items-center justify-center rounded-2xl border border-rose-500/40 bg-rose-500/10 text-rose-400">
                <Loader2 className="h-9 w-9 animate-spin" aria-hidden="true" />
              </div>
              <div className="space-y-1.5">
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  {phase === "opening" ? "Opening link..." : "Verifying..."}
                </h1>
                <p className="text-sm text-slate-400">
                  {phase === "opening"
                    ? "Verified safe. Redirecting now."
                    : "Checking link security on-device."}
                </p>
              </div>
              <RequestIdBadge value={requestId} />
            </div>
          )}

          {phase === "safe" && (
            <div className="flex flex-col items-center gap-5 py-4">
              <div className="flex h-20 w-20 items-center justify-center rounded-2xl border border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
                <ShieldCheck className="h-10 w-10" aria-hidden="true" />
              </div>
              <div className="space-y-1.5">
                <span className="inline-block font-mono text-xs font-bold tracking-widest text-emerald-400">
                  VERIFIED
                </span>
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  Redirected
                </h1>
                <p className="text-sm text-slate-400">
                  {headline || "This link passed verification and opened safely."}
                </p>
              </div>
              <RequestIdBadge value={requestId} />
              <button
                type="button"
                onClick={resetToReady}
                className="min-h-[48px] w-full cursor-pointer rounded-xl border border-white/15 bg-white/5 px-5 text-sm font-semibold text-white transition hover:bg-white/10"
              >
                Done
              </button>
            </div>
          )}

          {(phase === "blocked" || phase === "invalid") && (
            <div className="flex flex-col items-center gap-5 py-4">
              <div className="flex h-20 w-20 items-center justify-center rounded-2xl border border-rose-500/45 bg-rose-500/15 text-rose-400">
                <ShieldBan className="h-10 w-10" aria-hidden="true" />
              </div>
              <div className="space-y-1.5">
                <span className="inline-block font-mono text-xs font-bold tracking-widest text-rose-400">
                  {phase === "invalid" ? "INVALID LINK" : "BLOCKED"}
                </span>
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  Link blocked
                </h1>
                <p className="text-sm text-slate-400">
                  This link has been blocked for your protection.
                </p>
              </div>
              <RequestIdBadge value={requestId} />
              <button
                type="button"
                onClick={resetToReady}
                className="min-h-[48px] w-full cursor-pointer rounded-xl bg-rose-600 px-5 text-sm font-bold text-white transition hover:bg-rose-500"
              >
                Done
              </button>
            </div>
          )}

          {phase === "suspicious" && (
            <div className="flex flex-col items-center gap-5 py-4">
              <div className="flex h-20 w-20 items-center justify-center rounded-2xl border border-amber-500/45 bg-amber-500/15 text-amber-400">
                <AlertTriangle className="h-10 w-10" aria-hidden="true" />
              </div>
              <div className="space-y-1.5">
                <span className="inline-block font-mono text-xs font-bold tracking-widest text-amber-400">
                  SUSPICIOUS
                </span>
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  Suspicious link
                </h1>
                <p className="text-sm text-slate-400">
                  This link shows suspicious patterns. Go back unless you trust the source.
                </p>
              </div>
              <RequestIdBadge value={requestId} />
              <div className="flex w-full flex-col gap-2.5 sm:flex-row">
                <button
                  type="button"
                  onClick={resetToReady}
                  className="min-h-[48px] flex-1 cursor-pointer rounded-xl bg-white/10 px-4 text-sm font-bold text-white transition hover:bg-white/15"
                >
                  Go Back
                </button>
                <button
                  type="button"
                  onClick={() => openDestinationDirectly()}
                  className="min-h-[48px] flex-1 cursor-pointer rounded-xl border border-amber-500/45 bg-amber-500/15 px-4 text-sm font-bold text-amber-200 transition hover:bg-amber-500/25"
                >
                  Continue Anyway
                </button>
              </div>
            </div>
          )}

          {phase === "hold" && (
            <div className="flex flex-col items-center gap-5 py-4">
              <div className="flex h-20 w-20 items-center justify-center rounded-2xl border border-sky-500/40 bg-sky-500/10 text-sky-400">
                <PauseCircle className="h-10 w-10" aria-hidden="true" />
              </div>
              <div className="space-y-1.5">
                <span className="inline-block font-mono text-xs font-bold tracking-widest text-sky-400">
                  NOT VERIFIED
                </span>
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  Couldn&apos;t verify link
                </h1>
                <p className="text-sm text-slate-400">
                  This link was held and has not been opened.
                </p>
              </div>
              <RequestIdBadge value={requestId} />
              <button
                type="button"
                onClick={resetToReady}
                className="min-h-[48px] w-full cursor-pointer rounded-xl border border-white/15 bg-white/5 px-5 text-sm font-semibold text-white transition hover:bg-white/10"
              >
                Done
              </button>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
