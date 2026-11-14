import { useCallback, useEffect, useRef, useState } from "react";
import { Capacitor } from "@capacitor/core";
import { App as CapacitorApp } from "@capacitor/app";
import { Browser } from "@capacitor/browser";
import {
  ShieldCheck,
  ShieldBan,
  AlertTriangle,
  ShieldAlert,
  PauseCircle,
  Loader2,
  Copy,
  Check,
  ExternalLink,
  ArrowLeft,
  Lock
} from "lucide-react";
import { verifyDestination } from "./security/verificationService.js";

const isNative = Capacitor.isNativePlatform();

const SCAN_STAGES = [
  "Layer 03/30 • Anti-Evasion & NFKC Normalization",
  "Layer 09/30 • Homograph & Brand Spoof Shield",
  "Layer 16/30 • APK, Cert & Archive Malware Check",
  "Layer 20/30 • Base64, Hex & Redirect Propagator",
  "Layer 27/30 • Cross-Layer Threat Correlator"
];

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

function getAmbientGlow(phase) {
  switch (phase) {
    case "blocked":
    case "invalid":
      return "bg-[radial-gradient(ellipse_75%_55%_at_50%_20%,rgba(244,63,94,0.22),transparent_70%)]";
    case "suspicious":
      return "bg-[radial-gradient(ellipse_75%_55%_at_50%_20%,rgba(245,158,11,0.20),transparent_70%)]";
    case "hold":
      return "bg-[radial-gradient(ellipse_75%_55%_at_50%_20%,rgba(56,189,248,0.18),transparent_70%)]";
    case "checking":
    case "opening":
      return "bg-[radial-gradient(ellipse_75%_55%_at_50%_20%,rgba(99,102,241,0.20),transparent_70%)]";
    default:
      return "bg-[radial-gradient(ellipse_75%_55%_at_50%_20%,rgba(16,185,129,0.17),transparent_70%)]";
  }
}

function AnimatedOrb({ phase }) {
  if (phase === "checking" || phase === "opening") {
    return (
      <div className="relative flex h-28 w-28 items-center justify-center">
        <div className="sg-pulse-ring absolute inset-0 rounded-full border border-indigo-400/45" />
        <div className="sg-pulse-ring-delay absolute inset-0 rounded-full border border-cyan-400/35" />
        <div className="sg-spin-fast absolute inset-1 rounded-full border-2 border-dashed border-indigo-400/55" />
        <div className="sg-spin-reverse absolute inset-3.5 rounded-full border-2 border-t-cyan-400 border-r-transparent border-b-indigo-400/60 border-l-transparent" />
        <div className="relative flex h-16 w-16 items-center justify-center overflow-hidden rounded-2xl border border-indigo-400/45 bg-indigo-500/15 text-indigo-300 shadow-[0_0_28px_rgba(99,102,241,0.35)]">
          <div className="sg-scan-sweep pointer-events-none absolute inset-x-0 h-0.5 bg-gradient-to-r from-transparent via-cyan-300 to-transparent" />
          <Loader2 className="h-8 w-8 animate-spin" aria-hidden="true" />
        </div>
      </div>
    );
  }

  if (phase === "blocked" || phase === "invalid") {
    return (
      <div className="relative flex h-28 w-28 items-center justify-center">
        <div className="sg-pulse-ring absolute inset-0 rounded-full border border-rose-500/55" />
        <div className="sg-pulse-ring-delay absolute inset-0 rounded-full border border-rose-500/35" />
        <div className="absolute inset-2 rounded-full border border-rose-500/30" />
        <div className="relative flex h-20 w-20 items-center justify-center rounded-2xl border border-rose-500/55 bg-rose-500/15 text-rose-400 shadow-[0_0_32px_rgba(244,63,94,0.35)]">
          <ShieldBan className="h-10 w-10" aria-hidden="true" />
        </div>
      </div>
    );
  }

  if (phase === "suspicious") {
    return (
      <div className="relative flex h-28 w-28 items-center justify-center">
        <div className="sg-pulse-ring absolute inset-0 rounded-full border border-amber-400/50" />
        <div className="sg-spin-slow absolute inset-1.5 rounded-full border border-dashed border-amber-400/45" />
        <div className="relative flex h-20 w-20 items-center justify-center rounded-2xl border border-amber-500/50 bg-amber-500/15 text-amber-400 shadow-[0_0_30px_rgba(245,158,11,0.3)]">
          <AlertTriangle className="h-10 w-10" aria-hidden="true" />
        </div>
      </div>
    );
  }

  if (phase === "hold") {
    return (
      <div className="relative flex h-28 w-28 items-center justify-center">
        <div className="sg-spin-slow absolute inset-1.5 rounded-full border border-dashed border-sky-400/45" />
        <div className="sg-pulse-ring absolute inset-2 rounded-full border border-sky-400/40" />
        <div className="relative flex h-20 w-20 items-center justify-center rounded-2xl border border-sky-500/45 bg-sky-500/15 text-sky-400 shadow-[0_0_28px_rgba(56,189,248,0.28)]">
          <ShieldAlert className="h-10 w-10" aria-hidden="true" />
        </div>
      </div>
    );
  }

  return (
    <div className="sg-float-breathe relative flex h-28 w-28 items-center justify-center">
      <div className="sg-pulse-ring absolute inset-0 rounded-full border border-emerald-400/45" />
      <div className="sg-spin-slow absolute inset-1.5 rounded-full border border-dashed border-emerald-400/35" />
      <div className="relative flex h-20 w-20 items-center justify-center overflow-hidden rounded-2xl border border-emerald-500/45 bg-emerald-500/12 text-emerald-400 shadow-[0_0_30px_rgba(16,185,129,0.25)]">
        <div className="sg-scan-sweep pointer-events-none absolute inset-x-0 h-0.5 bg-gradient-to-r from-transparent via-emerald-300/80 to-transparent" />
        <ShieldCheck className="h-10 w-10" aria-hidden="true" />
      </div>
    </div>
  );
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
    <div className="flex w-full items-center justify-between gap-3 rounded-xl border border-white/10 bg-[#0b0e14]/90 px-4 py-3 text-left transition-colors hover:border-white/20">
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
        className="flex h-10 w-10 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-white/10 bg-white/5 text-slate-300 transition hover:bg-white/10 hover:text-white active:scale-95"
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
  const [holdChecksPassed, setHoldChecksPassed] = useState(false);
  const [displayHost, setDisplayHost] = useState("");
  const [scanStageIdx, setScanStageIdx] = useState(0);

  const destinationRef = useRef("");
  const processingRef = useRef(false);
  const lastUrlRef = useRef("");
  const lastReceivedAtRef = useRef(0);
  const mountedRef = useRef(true);

  useEffect(() => {
    if (phase !== "checking" && phase !== "opening") return undefined;
    const timer = window.setInterval(() => {
      setScanStageIdx((prev) => (prev + 1) % SCAN_STAGES.length);
    }, 320);
    return () => window.clearInterval(timer);
  }, [phase]);

  const openDestinationDirectly = useCallback(async (targetUrl) => {
    const url = targetUrl || destinationRef.current;
    if (!url || !validateHttpUrl(url)) {
      if (mountedRef.current) setPhase("invalid");
      return;
    }

    try {
      if (isNative) {
        try {
          await Browser.open({
            url,
            toolbarColor: "#090b10"
          });
        } catch {
          window.location.assign(url);
        }
      } else {
        window.location.assign(url);
      }
    } catch {
      if (mountedRef.current) {
        setHoldChecksPassed(false);
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
      setHoldChecksPassed(false);
      setDisplayHost("");
      setScanStageIdx(0);

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
        setDisplayHost(result?.localVerification?.redactedDestination?.displayHost || "");

        const outcome = classifyResult(result);

        if (outcome === "safe") {
          setPhase("opening");
          await openDestinationDirectly(url);
          if (mountedRef.current) {
            setPhase("safe");
          }
          return;
        }

        if (outcome === "hold") {
          const passedLocal =
            result?.verificationStatus === "COMPLETED" &&
            result?.localVerification?.decision === "REPUTATION_CHECK_REQUIRED";
          setHoldChecksPassed(passedLocal);
        }

        setPhase(outcome);
      } catch {
        if (mountedRef.current) {
          setHoldChecksPassed(false);
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
    setHoldChecksPassed(false);
    setDisplayHost("");
    setPhase("ready");
  };

  const cardAnimationClass =
    phase === "blocked" || phase === "invalid"
      ? "sg-alert-shake"
      : "sg-card-enter";

  return (
    <div className="relative flex min-h-screen flex-col overflow-hidden text-slate-100">
      <div
        aria-hidden="true"
        className={`pointer-events-none fixed inset-0 transition-all duration-700 ${getAmbientGlow(phase)}`}
      />
      <div
        aria-hidden="true"
        className="sg-cyber-grid pointer-events-none fixed inset-0"
      />

      <header className="relative z-10 border-b border-white/10 bg-[#090b10]/85 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-2xl items-center justify-between px-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-emerald-500/35 bg-emerald-500/10 text-emerald-400">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </div>
            <span className="text-sm font-extrabold tracking-widest text-white">
              SAFEGATE
            </span>
          </div>

          <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-[11px] font-semibold text-slate-300">
            <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
            ON-DEVICE
          </div>
        </div>
      </header>

      <main className="relative z-10 flex flex-1 items-center justify-center px-4 py-8">
        <section
          key={phase}
          className={`${cardAnimationClass} w-full max-w-md rounded-2xl border border-white/12 bg-[#12161f]/95 p-6 text-center shadow-[0_24px_80px_rgba(0,0,0,0.65)] backdrop-blur-xl sm:p-8`}
          aria-live="polite"
        >
          {phase === "ready" && (
            <div className="flex flex-col items-center gap-5 py-2">
              <AnimatedOrb phase="ready" />

              <div className="space-y-2">
                <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-bold tracking-widest text-emerald-400">
                  <Lock className="h-3.5 w-3.5" aria-hidden="true" />
                  30-LAYER ZERO-EGRESS GUARD
                </span>
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  SafeGate Ready
                </h1>
                <p className="text-sm leading-relaxed text-slate-400">
                  Link protection is active. Any clicked link is verified automatically on your device before opening.
                </p>
              </div>

              <div className="grid w-full grid-cols-3 gap-2 pt-1 text-center">
                <div className="rounded-xl border border-white/8 bg-[#0b0e14]/80 px-2 py-2.5">
                  <div className="font-mono text-[10px] font-bold text-emerald-400">01</div>
                  <div className="mt-0.5 text-[11px] font-semibold text-slate-300">Intercept</div>
                </div>
                <div className="rounded-xl border border-white/8 bg-[#0b0e14]/80 px-2 py-2.5">
                  <div className="font-mono text-[10px] font-bold text-emerald-400">02</div>
                  <div className="mt-0.5 text-[11px] font-semibold text-slate-300">30 Checks</div>
                </div>
                <div className="rounded-xl border border-white/8 bg-[#0b0e14]/80 px-2 py-2.5">
                  <div className="font-mono text-[10px] font-bold text-emerald-400">03</div>
                  <div className="mt-0.5 text-[11px] font-semibold text-slate-300">Zero Data Out</div>
                </div>
              </div>
            </div>
          )}

          {(phase === "checking" || phase === "opening") && (
            <div className="flex flex-col items-center gap-5 py-2">
              <AnimatedOrb phase={phase} />

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

              <div className="w-full space-y-2">
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/10">
                  <div className="sg-progress-slide h-full w-2/5 rounded-full bg-gradient-to-r from-indigo-500 via-cyan-400 to-emerald-400" />
                </div>
                <div className="truncate font-mono text-[11px] text-indigo-300">
                  {phase === "opening"
                    ? "All 30 on-device checks passed"
                    : SCAN_STAGES[scanStageIdx]}
                </div>
              </div>

              <RequestIdBadge value={requestId} />
            </div>
          )}

          {phase === "safe" && (
            <div className="flex flex-col items-center gap-5 py-2">
              <AnimatedOrb phase="safe" />
              <div className="space-y-1.5">
                <span className="inline-block font-mono text-xs font-bold tracking-widest text-emerald-400">
                  VERIFIED SAFE
                </span>
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  Redirected
                </h1>
                <p className="text-sm text-slate-400">
                  {headline || "This link passed all 30 checks and opened safely."}
                </p>
              </div>
              <RequestIdBadge value={requestId} />
              <button
                type="button"
                onClick={resetToReady}
                className="min-h-[48px] w-full cursor-pointer rounded-xl border border-emerald-500/35 bg-emerald-500/15 px-5 text-sm font-bold text-emerald-200 transition hover:bg-emerald-500/25 active:scale-[0.98]"
              >
                Done
              </button>
            </div>
          )}

          {(phase === "blocked" || phase === "invalid") && (
            <div className="flex flex-col items-center gap-5 py-2">
              <AnimatedOrb phase="blocked" />
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
                className="min-h-[48px] w-full cursor-pointer rounded-xl bg-rose-600 px-5 text-sm font-bold text-white shadow-[0_8px_24px_rgba(225,29,72,0.35)] transition hover:bg-rose-500 active:scale-[0.98]"
              >
                Done
              </button>
            </div>
          )}

          {phase === "suspicious" && (
            <div className="flex flex-col items-center gap-5 py-2">
              <AnimatedOrb phase="suspicious" />
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
                  className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 rounded-xl bg-white/10 px-4 text-sm font-bold text-white transition hover:bg-white/15 active:scale-[0.98]"
                >
                  <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                  Go Back
                </button>
                <button
                  type="button"
                  onClick={() => openDestinationDirectly()}
                  className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 rounded-xl border border-amber-500/45 bg-amber-500/15 px-4 text-sm font-bold text-amber-200 transition hover:bg-amber-500/25 active:scale-[0.98]"
                >
                  Open Anyway
                  <ExternalLink className="h-4 w-4" aria-hidden="true" />
                </button>
              </div>
            </div>
          )}

          {phase === "hold" && (
            <div className="flex flex-col items-center gap-5 py-2">
              {holdChecksPassed ? (
                <AnimatedOrb phase="hold" />
              ) : (
                <div className="flex h-20 w-20 items-center justify-center rounded-2xl border border-sky-500/40 bg-sky-500/10 text-sky-400">
                  <PauseCircle className="h-10 w-10" aria-hidden="true" />
                </div>
              )}

              <div className="space-y-1.5">
                <span className="inline-block font-mono text-xs font-bold tracking-widest text-sky-400">
                  {holdChecksPassed ? "PASSED 30 CHECKS • HELD" : "NOT VERIFIED"}
                </span>
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  {holdChecksPassed ? "Unverified domain" : "Couldn't verify link"}
                </h1>
                <p className="text-sm text-slate-400">
                  {holdChecksPassed
                    ? `${displayHost ? `${displayHost} passed` : "Passed"} all 30 on-device checks, but isn't on the official allow-list.`
                    : "This link was held and has not been opened."}
                </p>
              </div>

              <RequestIdBadge value={requestId} />

              {holdChecksPassed ? (
                <div className="flex w-full flex-col gap-2.5 sm:flex-row">
                  <button
                    type="button"
                    onClick={resetToReady}
                    className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 rounded-xl bg-white/10 px-4 text-sm font-bold text-white transition hover:bg-white/15 active:scale-[0.98]"
                  >
                    <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                    Go Back
                  </button>
                  <button
                    type="button"
                    onClick={() => openDestinationDirectly()}
                    className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 rounded-xl border border-sky-500/45 bg-sky-500/15 px-4 text-sm font-bold text-sky-200 transition hover:bg-sky-500/25 active:scale-[0.98]"
                  >
                    Open Anyway
                    <ExternalLink className="h-4 w-4" aria-hidden="true" />
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={resetToReady}
                  className="min-h-[48px] w-full cursor-pointer rounded-xl border border-white/15 bg-white/5 px-5 text-sm font-semibold text-white transition hover:bg-white/10 active:scale-[0.98]"
                >
                  Done
                </button>
              )}
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
