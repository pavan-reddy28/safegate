import { useCallback, useEffect, useRef, useState } from "react";
import { Capacitor } from "@capacitor/core";
import { App as CapacitorApp } from "@capacitor/app";
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
  RefreshCw,
  Globe
} from "lucide-react";
import {
  verifyDestination,
  checkCloudOverrideForRequest
} from "./security/verificationService.js";
import {
  isValidExternalHttpUrl,
  openInExternalBrowser
} from "./native/externalBrowser.js";

const isNative = Capacitor.isNativePlatform();

const SCAN_STAGES = [
  "Inspecting web address",
  "Scanning domain trust",
  "Checking redirect safety",
  "Analyzing threat signals",
  "Finalizing protection check"
];

const WAVE_DELAYS = [
  "0ms",
  "140ms",
  "280ms",
  "420ms",
  "560ms",
  "420ms",
  "280ms",
  "140ms",
  "0ms"
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

function getPhaseTheme(phase) {
  switch (phase) {
    case "blocked":
    case "invalid":
      return {
        primaryGlow:
          "bg-[radial-gradient(ellipse_75%_55%_at_50%_20%,rgba(244,63,94,0.28),transparent_70%)]",
        secondaryGlow:
          "bg-[radial-gradient(circle_at_80%_78%,rgba(225,29,72,0.16),transparent_55%)]",
        cardRing: "border-rose-500/25 shadow-[0_28px_90px_rgba(244,63,94,0.16)]",
        topEdge: "via-rose-400/75"
      };
    case "suspicious":
      return {
        primaryGlow:
          "bg-[radial-gradient(ellipse_75%_55%_at_50%_20%,rgba(245,158,11,0.25),transparent_70%)]",
        secondaryGlow:
          "bg-[radial-gradient(circle_at_22%_80%,rgba(234,88,12,0.15),transparent_55%)]",
        cardRing: "border-amber-500/25 shadow-[0_28px_90px_rgba(245,158,11,0.15)]",
        topEdge: "via-amber-400/75"
      };
    case "hold":
      return {
        primaryGlow:
          "bg-[radial-gradient(ellipse_75%_55%_at_50%_20%,rgba(56,189,248,0.24),transparent_70%)]",
        secondaryGlow:
          "bg-[radial-gradient(circle_at_78%_75%,rgba(14,165,233,0.16),transparent_55%)]",
        cardRing: "border-sky-400/25 shadow-[0_28px_90px_rgba(56,189,248,0.16)]",
        topEdge: "via-sky-400/75"
      };
    case "checking":
    case "opening":
      return {
        primaryGlow:
          "bg-[radial-gradient(ellipse_75%_55%_at_50%_20%,rgba(99,102,241,0.26),transparent_70%)]",
        secondaryGlow:
          "bg-[radial-gradient(circle_at_75%_75%,rgba(34,211,238,0.18),transparent_55%)]",
        cardRing: "border-indigo-400/30 shadow-[0_28px_90px_rgba(99,102,241,0.2)]",
        topEdge: "via-cyan-400/80"
      };
    default:
      return {
        primaryGlow:
          "bg-[radial-gradient(ellipse_75%_55%_at_50%_20%,rgba(16,185,129,0.22),transparent_70%)]",
        secondaryGlow:
          "bg-[radial-gradient(circle_at_78%_78%,rgba(6,182,212,0.16),transparent_55%)]",
        cardRing: "border-emerald-500/25 shadow-[0_28px_90px_rgba(16,185,129,0.16)]",
        topEdge: "via-emerald-400/75"
      };
  }
}

function AnimatedOrb({ phase }) {
  if (phase === "checking" || phase === "opening") {
    return (
      <div className="relative flex h-32 w-32 items-center justify-center">
        <div className="sg-pulse-ring absolute inset-0 rounded-full border border-cyan-400/50" />
        <div className="sg-pulse-ring-delay absolute inset-0 rounded-full border border-indigo-400/40" />
        <div
          className="sg-spin-fast absolute inset-1 rounded-full opacity-55"
          style={{
            background:
              "conic-gradient(from 0deg, transparent 0deg, rgba(34,211,238,0.45) 55deg, transparent 110deg)"
          }}
        />
        <div className="sg-spin-fast absolute inset-1.5 rounded-full border-2 border-dashed border-indigo-400/60">
          <span className="absolute -top-1 left-1/2 h-2.5 w-2.5 -translate-x-1/2 rounded-full bg-cyan-300 shadow-[0_0_12px_rgba(34,211,238,0.95)]" />
        </div>
        <div className="sg-spin-reverse absolute inset-4 rounded-full border-2 border-t-cyan-300 border-r-transparent border-b-indigo-400/70 border-l-transparent" />
        <div className="relative flex h-18 w-18 items-center justify-center overflow-hidden rounded-2xl border border-cyan-400/50 bg-gradient-to-br from-indigo-500/25 to-cyan-500/20 text-cyan-300 shadow-[0_0_35px_rgba(34,211,238,0.35)]">
          <div className="sg-scan-sweep pointer-events-none absolute inset-x-0 h-0.5 bg-gradient-to-r from-transparent via-cyan-200 to-transparent shadow-[0_0_10px_#67e8f9]" />
          <Loader2 className="h-9 w-9 animate-spin" aria-hidden="true" />
        </div>
      </div>
    );
  }

  if (phase === "blocked" || phase === "invalid") {
    return (
      <div className="relative flex h-32 w-32 items-center justify-center">
        <div className="sg-pulse-ring absolute inset-0 rounded-full border border-rose-500/60" />
        <div className="sg-pulse-ring-delay absolute inset-0 rounded-full border border-rose-500/40" />
        <div className="sg-spin-slow absolute inset-2 rounded-full border border-dashed border-rose-400/45">
          <span className="absolute -top-1 left-1/2 h-2 w-2 -translate-x-1/2 rounded-full bg-rose-400 shadow-[0_0_10px_rgba(244,63,94,0.9)]" />
        </div>
        <div className="sg-float-breathe relative flex h-20 w-20 items-center justify-center overflow-hidden rounded-2xl border border-rose-500/60 bg-gradient-to-br from-rose-500/25 to-rose-900/30 text-rose-400 shadow-[0_0_38px_rgba(244,63,94,0.4)]">
          <div className="sg-scan-sweep pointer-events-none absolute inset-x-0 h-0.5 bg-gradient-to-r from-transparent via-rose-300/80 to-transparent" />
          <ShieldBan className="h-10 w-10" aria-hidden="true" />
        </div>
      </div>
    );
  }

  if (phase === "suspicious") {
    return (
      <div className="relative flex h-32 w-32 items-center justify-center">
        <div className="sg-pulse-ring absolute inset-0 rounded-full border border-amber-400/55" />
        <div className="sg-pulse-ring-delay absolute inset-1 rounded-full border border-orange-400/35" />
        <div className="sg-spin-medium absolute inset-2 rounded-full border border-dashed border-amber-400/50">
          <span className="absolute -top-1 left-1/2 h-2 w-2 -translate-x-1/2 rounded-full bg-amber-300 shadow-[0_0_10px_rgba(251,191,36,0.9)]" />
        </div>
        <div className="sg-float-breathe relative flex h-20 w-20 items-center justify-center overflow-hidden rounded-2xl border border-amber-500/55 bg-gradient-to-br from-amber-500/20 to-orange-500/15 text-amber-400 shadow-[0_0_34px_rgba(245,158,11,0.32)]">
          <div className="sg-scan-sweep pointer-events-none absolute inset-x-0 h-0.5 bg-gradient-to-r from-transparent via-amber-200/80 to-transparent" />
          <AlertTriangle className="h-10 w-10" aria-hidden="true" />
        </div>
      </div>
    );
  }

  if (phase === "hold") {
    return (
      <div className="relative flex h-32 w-32 items-center justify-center">
        <div className="sg-pulse-ring absolute inset-0 rounded-full border border-sky-400/50" />
        <div className="sg-pulse-ring-delay absolute inset-1 rounded-full border border-cyan-400/30" />
        <div className="sg-spin-slow absolute inset-2 rounded-full border border-dashed border-sky-400/50">
          <span className="absolute -top-1 left-1/2 h-2 w-2 -translate-x-1/2 rounded-full bg-sky-300 shadow-[0_0_10px_rgba(56,189,248,0.9)]" />
        </div>
        <div className="sg-spin-reverse-slow absolute inset-4 rounded-full border border-sky-300/25" />
        <div className="sg-float-breathe relative flex h-20 w-20 items-center justify-center overflow-hidden rounded-2xl border border-sky-400/50 bg-gradient-to-br from-sky-500/20 to-indigo-500/15 text-sky-300 shadow-[0_0_32px_rgba(56,189,248,0.3)]">
          <div className="sg-scan-sweep pointer-events-none absolute inset-x-0 h-0.5 bg-gradient-to-r from-transparent via-sky-200/80 to-transparent" />
          <ShieldAlert className="h-10 w-10" aria-hidden="true" />
        </div>
      </div>
    );
  }

  return (
    <div className="relative flex h-32 w-32 items-center justify-center">
      <div className="sg-pulse-ring absolute inset-0 rounded-full border border-emerald-400/50" />
      <div className="sg-pulse-ring-delay absolute inset-0 rounded-full border border-cyan-400/35" />
      <div
        className="sg-spin-slow absolute inset-1.5 rounded-full opacity-45"
        style={{
          background:
            "conic-gradient(from 0deg, transparent 0deg, rgba(16,185,129,0.38) 65deg, transparent 130deg)"
        }}
      />
      <div className="sg-spin-medium absolute inset-1.5 rounded-full border border-dashed border-emerald-400/45">
        <span className="absolute -top-1 left-1/2 h-2.5 w-2.5 -translate-x-1/2 rounded-full bg-emerald-300 shadow-[0_0_12px_rgba(52,211,153,0.95)]" />
      </div>
      <div className="sg-spin-reverse-slow absolute inset-4 rounded-full border border-cyan-400/30">
        <span className="absolute -bottom-1 left-1/2 h-1.5 w-1.5 -translate-x-1/2 rounded-full bg-cyan-300 shadow-[0_0_8px_rgba(34,211,238,0.9)]" />
      </div>
      <div className="sg-float-breathe relative flex h-20 w-20 items-center justify-center overflow-hidden rounded-2xl border border-emerald-400/50 bg-gradient-to-br from-emerald-500/20 to-cyan-500/15 text-emerald-300 shadow-[0_0_36px_rgba(16,185,129,0.3)]">
        <div className="sg-scan-sweep pointer-events-none absolute inset-x-0 h-0.5 bg-gradient-to-r from-transparent via-emerald-200 to-transparent shadow-[0_0_10px_#6ee7b7]" />
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
    <div className="flex w-full items-center justify-between gap-3 rounded-xl border border-white/10 bg-[#080b11]/90 px-4 py-3 text-left transition-colors hover:border-white/20">
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
        className="flex h-11 w-11 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-white/10 bg-white/5 text-slate-300 transition hover:bg-white/10 hover:text-white active:scale-95"
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
  const [checkingCloud, setCheckingCloud] = useState(false);
  const [cloudNotice, setCloudNotice] = useState("");

  const destinationRef = useRef("");
  const lastResultRef = useRef(null);
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
    if (!url || !isValidExternalHttpUrl(url)) {
      if (mountedRef.current) setPhase("invalid");
      return;
    }

    try {
      await openInExternalBrowser(url);
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
      lastResultRef.current = null;
      setRequestId(localId);
      setHeadline("");
      setHoldChecksPassed(false);
      setDisplayHost("");
      setCloudNotice("");
      setCheckingCloud(false);
      setScanStageIdx(0);

      if (!isValidExternalHttpUrl(url)) {
        setPhase("invalid");
        return;
      }

      processingRef.current = true;
      setPhase("checking");

      try {
        const result = await verifyDestination(url);
        if (!mountedRef.current) return;

        lastResultRef.current = result;
        setRequestId(getRequestId(result, localId));
        setHeadline(result?.riskSummary?.headline || "");
        setDisplayHost(
          result?.localVerification?.redactedDestination?.displayHost || ""
        );

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

  const handleCheckCloudStatus = useCallback(async () => {
    if (!requestId || checkingCloud || processingRef.current) return;

    setCheckingCloud(true);
    setCloudNotice("");

    try {
      const decision = await checkCloudOverrideForRequest({
        rawUrl: destinationRef.current,
        requestId,
        lastResult: lastResultRef.current
      });
      if (!mountedRef.current) return;

      if (decision.allowOpen) {
        setHeadline("Approved by operator. Handed off to your browser.");
        setPhase("opening");
        await openDestinationDirectly(destinationRef.current);
        if (mountedRef.current) {
          setPhase("safe");
        }
        return;
      }

      if (decision.blocked) {
        setPhase("blocked");
        setCloudNotice("Still blocked");
        return;
      }

      if (decision.configured === false) {
        setCloudNotice("Cloud check not configured");
      } else if (decision.offline) {
        setCloudNotice("Could not reach cloud status");
      } else {
        setCloudNotice("No override update yet");
      }
    } catch {
      if (mountedRef.current) {
        setCloudNotice("Could not reach cloud status");
      }
    } finally {
      if (mountedRef.current) {
        setCheckingCloud(false);
      }
    }
  }, [requestId, checkingCloud, openDestinationDirectly]);

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
    if (processingRef.current || checkingCloud) return;
    destinationRef.current = "";
    lastResultRef.current = null;
    lastUrlRef.current = "";
    setRequestId("");
    setHeadline("");
    setHoldChecksPassed(false);
    setDisplayHost("");
    setCloudNotice("");
    setCheckingCloud(false);
    setPhase("ready");
  };

  const theme = getPhaseTheme(phase);
  const cardAnimationClass =
    phase === "blocked" || phase === "invalid"
      ? "sg-alert-shake"
      : "sg-card-enter";

  return (
    <div className="relative flex min-h-screen flex-col overflow-hidden bg-[#07090e] text-slate-100">
      <div
        aria-hidden="true"
        className={`sg-aurora-drift pointer-events-none fixed inset-0 transition-all duration-700 ${theme.primaryGlow}`}
      />
      <div
        aria-hidden="true"
        className={`sg-aurora-drift-alt pointer-events-none fixed inset-0 transition-all duration-700 ${theme.secondaryGlow}`}
      />
      <div
        aria-hidden="true"
        className="sg-cyber-grid pointer-events-none fixed inset-0"
      />

      <header className="relative z-10 border-b border-white/10 bg-[#07090e]/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-2xl items-center justify-between px-5">
          <div className="flex items-center gap-3">
            <div className="relative flex h-10 w-10 items-center justify-center rounded-xl border border-emerald-400/40 bg-emerald-500/12 text-emerald-300 shadow-[0_0_20px_rgba(16,185,129,0.22)]">
              <ShieldCheck className="h-5 w-5" aria-hidden="true" />
            </div>
            <span className="text-sm font-extrabold tracking-widest text-white">
              SAFEGATE
            </span>
          </div>
        </div>
      </header>

      <main className="relative z-10 flex flex-1 items-center justify-center px-4 py-8">
        <section
          key={phase}
          className={`${cardAnimationClass} ${theme.cardRing} relative w-full max-w-md overflow-hidden rounded-3xl border bg-[#0e131d]/92 p-6 text-center backdrop-blur-2xl sm:p-8`}
          aria-live="polite"
        >
          <div
            aria-hidden="true"
            className={`pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent ${theme.topEdge} to-transparent`}
          />

          {phase === "ready" && (
            <div className="flex flex-col items-center gap-7 py-6">
              <AnimatedOrb phase="ready" />

              <div
                aria-hidden="true"
                className="flex h-11 w-full items-center justify-center gap-1.5 rounded-2xl border border-emerald-500/15 bg-[#080b11]/85 px-5"
              >
                {WAVE_DELAYS.map((delay, idx) => (
                  <span
                    key={idx}
                    style={{ animationDelay: delay }}
                    className={`sg-wave-bar w-1.5 rounded-full bg-gradient-to-t from-emerald-500/70 to-cyan-300 ${
                      idx === 4
                        ? "h-6"
                        : idx === 3 || idx === 5
                          ? "h-5"
                          : idx === 2 || idx === 6
                            ? "h-4"
                            : "h-2.5"
                    }`}
                  />
                ))}
              </div>
            </div>
          )}

          {(phase === "checking" || phase === "opening") && (
            <div className="flex flex-col items-center gap-5 py-2">
              <AnimatedOrb phase={phase} />

              <div className="space-y-1.5">
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  {phase === "opening" ? "Opening in Browser..." : "Checking Link..."}
                </h1>
                <p className="text-sm text-slate-400">
                  {phase === "opening"
                    ? "Link cleared. Redirecting to Chrome or your external browser."
                    : "Scanning destination before opening."}
                </p>
              </div>

              <div className="w-full space-y-2.5">
                <div className="h-2 w-full overflow-hidden rounded-full bg-white/10">
                  <div className="sg-progress-slide h-full w-2/5 rounded-full bg-gradient-to-r from-indigo-500 via-cyan-400 to-emerald-400 shadow-[0_0_12px_rgba(34,211,238,0.65)]" />
                </div>
                <div className="truncate font-mono text-[11px] font-medium text-cyan-300">
                  {phase === "opening"
                    ? "Launching external browser"
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
                <span className="inline-flex items-center gap-1.5 font-mono text-xs font-bold tracking-widest text-emerald-400">
                  <Globe className="h-3.5 w-3.5" aria-hidden="true" />
                  VERIFIED SAFE
                </span>
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  Opened in Browser
                </h1>
                <p className="text-sm text-slate-400">
                  {headline || "Verified safe and handed off to your browser."}
                </p>
              </div>
              <RequestIdBadge value={requestId} />
              <button
                type="button"
                onClick={resetToReady}
                className="relative min-h-[48px] w-full cursor-pointer overflow-hidden rounded-xl border border-emerald-400/40 bg-emerald-500/18 px-5 text-sm font-bold text-emerald-100 transition hover:bg-emerald-500/28 active:scale-[0.98]"
              >
                <span className="sg-shimmer-sweep pointer-events-none absolute inset-y-0 w-16 bg-gradient-to-r from-transparent via-white/20 to-transparent" />
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
                  Link Blocked
                </h1>
                <p className="text-sm text-slate-400">
                  {phase === "invalid"
                    ? "Malformed or unsupported link stopped safely."
                    : "Dangerous link stopped before it could open."}
                </p>
              </div>
              <RequestIdBadge value={requestId} />
              {cloudNotice && (
                <p data-testid="cloud-status-notice" className="text-xs font-medium text-slate-400">
                  {cloudNotice}
                </p>
              )}
              {phase === "blocked" ? (
                <div className="flex w-full flex-col gap-2.5 sm:flex-row">
                  <button
                    type="button"
                    onClick={handleCheckCloudStatus}
                    disabled={checkingCloud}
                    className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-white/15 bg-white/8 px-4 text-sm font-bold text-white transition hover:bg-white/14 active:scale-[0.98] disabled:cursor-wait disabled:opacity-60"
                  >
                    <RefreshCw
                      className={`h-4 w-4 ${checkingCloud ? "animate-spin" : ""}`}
                      aria-hidden="true"
                    />
                    {checkingCloud ? "Checking..." : "Check Status"}
                  </button>
                  <button
                    type="button"
                    onClick={resetToReady}
                    className="relative min-h-[48px] flex-1 cursor-pointer overflow-hidden whitespace-nowrap rounded-xl bg-rose-600 px-5 text-sm font-bold text-white shadow-[0_10px_28px_rgba(225,29,72,0.4)] transition hover:bg-rose-500 active:scale-[0.98]"
                  >
                    <span className="sg-shimmer-sweep pointer-events-none absolute inset-y-0 w-16 bg-gradient-to-r from-transparent via-white/25 to-transparent" />
                    Done
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={resetToReady}
                  className="relative min-h-[48px] w-full cursor-pointer overflow-hidden whitespace-nowrap rounded-xl bg-rose-600 px-5 text-sm font-bold text-white shadow-[0_10px_28px_rgba(225,29,72,0.4)] transition hover:bg-rose-500 active:scale-[0.98]"
                >
                  <span className="sg-shimmer-sweep pointer-events-none absolute inset-y-0 w-16 bg-gradient-to-r from-transparent via-white/25 to-transparent" />
                  Done
                </button>
              )}
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
                  Caution Advised
                </h1>
                <p className="text-sm text-slate-400">
                  Unusual link patterns detected. Only open in browser if you trust the source.
                </p>
              </div>
              <RequestIdBadge value={requestId} />
              {cloudNotice && (
                <p data-testid="cloud-status-notice" className="text-xs font-medium text-slate-400">
                  {cloudNotice}
                </p>
              )}
              <div className="flex w-full flex-col gap-2.5">
                <div className="flex w-full flex-col gap-2.5 sm:flex-row">
                  <button
                    type="button"
                    onClick={resetToReady}
                    className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl bg-white/10 px-4 text-sm font-bold text-white transition hover:bg-white/15 active:scale-[0.98]"
                  >
                    <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                    Go Back
                  </button>
                  <button
                    type="button"
                    onClick={() => openDestinationDirectly()}
                    className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-amber-400/50 bg-amber-500/18 px-4 text-sm font-bold text-amber-100 transition hover:bg-amber-500/28 active:scale-[0.98]"
                  >
                    Open Anyway
                    <ExternalLink className="h-4 w-4" aria-hidden="true" />
                  </button>
                </div>
                <button
                  type="button"
                  onClick={handleCheckCloudStatus}
                  disabled={checkingCloud}
                  className="inline-flex min-h-[48px] w-full cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-white/15 bg-white/8 px-4 text-sm font-bold text-white transition hover:bg-white/14 active:scale-[0.98] disabled:cursor-wait disabled:opacity-60"
                >
                  <RefreshCw
                    className={`h-4 w-4 ${checkingCloud ? "animate-spin" : ""}`}
                    aria-hidden="true"
                  />
                  {checkingCloud ? "Checking..." : "Check Status"}
                </button>
              </div>
            </div>
          )}

          {phase === "hold" && (
            <div className="flex flex-col items-center gap-5 py-2">
              {holdChecksPassed ? (
                <AnimatedOrb phase="hold" />
              ) : (
                <div className="relative flex h-24 w-24 items-center justify-center rounded-2xl border border-sky-400/40 bg-sky-500/12 text-sky-400">
                  <PauseCircle className="h-11 w-11" aria-hidden="true" />
                </div>
              )}

              <div className="space-y-1.5">
                <span className="inline-block font-mono text-xs font-bold tracking-widest text-sky-400">
                  {holdChecksPassed ? "UNVERIFIED SITE" : "NOT VERIFIED"}
                </span>
                <h1 className="text-2xl font-extrabold tracking-tight text-white">
                  {holdChecksPassed ? "Proceed with caution" : "Verification paused"}
                </h1>
                <p className="text-sm text-slate-400">
                  {holdChecksPassed
                    ? `${displayHost || "This domain"} shows no active threat signals, but isn't a recognized brand.`
                    : "Could not complete link verification."}
                </p>
              </div>

              <RequestIdBadge value={requestId} />

              {cloudNotice && (
                <p data-testid="cloud-status-notice" className="text-xs font-medium text-slate-400">
                  {cloudNotice}
                </p>
              )}

              {holdChecksPassed ? (
                <div className="flex w-full flex-col gap-2.5">
                  <div className="flex w-full flex-col gap-2.5 sm:flex-row">
                    <button
                      type="button"
                      onClick={resetToReady}
                      className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl bg-white/10 px-4 text-sm font-bold text-white transition hover:bg-white/15 active:scale-[0.98]"
                    >
                      <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                      Go Back
                    </button>
                    <button
                      type="button"
                      onClick={() => openDestinationDirectly()}
                      className="relative inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 overflow-hidden whitespace-nowrap rounded-xl border border-sky-400/50 bg-sky-500/18 px-4 text-sm font-bold text-sky-100 transition hover:bg-sky-500/28 active:scale-[0.98]"
                    >
                      <span className="sg-shimmer-sweep pointer-events-none absolute inset-y-0 w-14 bg-gradient-to-r from-transparent via-white/15 to-transparent" />
                      Open Anyway
                      <ExternalLink className="h-4 w-4" aria-hidden="true" />
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={handleCheckCloudStatus}
                    disabled={checkingCloud}
                    className="inline-flex min-h-[48px] w-full cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-white/15 bg-white/8 px-4 text-sm font-bold text-white transition hover:bg-white/14 active:scale-[0.98] disabled:cursor-wait disabled:opacity-60"
                  >
                    <RefreshCw
                      className={`h-4 w-4 ${checkingCloud ? "animate-spin" : ""}`}
                      aria-hidden="true"
                    />
                    {checkingCloud ? "Checking..." : "Check Status"}
                  </button>
                </div>
              ) : (
                <div className="flex w-full flex-col gap-2.5 sm:flex-row">
                  <button
                    type="button"
                    onClick={handleCheckCloudStatus}
                    disabled={checkingCloud}
                    className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-white/15 bg-white/8 px-4 text-sm font-bold text-white transition hover:bg-white/14 active:scale-[0.98] disabled:cursor-wait disabled:opacity-60"
                  >
                    <RefreshCw
                      className={`h-4 w-4 ${checkingCloud ? "animate-spin" : ""}`}
                      aria-hidden="true"
                    />
                    {checkingCloud ? "Checking..." : "Check Status"}
                  </button>
                  <button
                    type="button"
                    onClick={resetToReady}
                    className="min-h-[48px] flex-1 cursor-pointer whitespace-nowrap rounded-xl border border-white/15 bg-white/5 px-5 text-sm font-semibold text-white transition hover:bg-white/10 active:scale-[0.98]"
                  >
                    Done
                  </button>
                </div>
              )}
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
