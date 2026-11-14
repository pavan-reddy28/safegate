import { useState } from "react";
import {
  ShieldCheck,
  ShieldBan,
  AlertTriangle,
  PauseCircle,
  Copy,
  Check,
  ExternalLink,
  RotateCcw,
  ChevronDown,
  ChevronUp,
  Lock
} from "lucide-react";

const CHECK_LABELS = [
  { key: "schemeAndEncodingCheck", label: "Scheme & Encoding" },
  { key: "networkAndIpIsolationCheck", label: "Network & IP Isolation" },
  { key: "homographAndBrandSpoofCheck", label: "Homograph & Brand Spoof" },
  { key: "malwareAndPathCheck", label: "Malware & Path Shield" },
  { key: "redirectAndSmugglingCheck", label: "Redirect & Smuggling" },
  { key: "smsScamLureCheck", label: "Scam & UPI Lure Engine" }
];

const OUTCOME_META = {
  safe: {
    badge: "VERIFIED OFFICIAL",
    icon: ShieldCheck,
    border: "border-emerald-500/40",
    bg: "bg-emerald-500/10",
    accentText: "text-emerald-300",
    badgeBg: "bg-emerald-500/15 text-emerald-300 border-emerald-500/35"
  },
  hold: {
    badge: "UNVERIFIED — HELD",
    icon: PauseCircle,
    border: "border-sky-500/40",
    bg: "bg-sky-500/10",
    accentText: "text-sky-300",
    badgeBg: "bg-sky-500/15 text-sky-300 border-sky-500/35"
  },
  suspicious: {
    badge: "SUSPICIOUS PATTERN",
    icon: AlertTriangle,
    border: "border-amber-500/40",
    bg: "bg-amber-500/10",
    accentText: "text-amber-300",
    badgeBg: "bg-amber-500/15 text-amber-300 border-amber-500/35"
  },
  blocked: {
    badge: "THREAT BLOCKED",
    icon: ShieldBan,
    border: "border-rose-500/45",
    bg: "bg-rose-500/10",
    accentText: "text-rose-300",
    badgeBg: "bg-rose-500/15 text-rose-300 border-rose-500/35"
  },
  invalid: {
    badge: "INVALID LINK",
    icon: ShieldBan,
    border: "border-rose-500/45",
    bg: "bg-rose-500/10",
    accentText: "text-rose-300",
    badgeBg: "bg-rose-500/15 text-rose-300 border-rose-500/35"
  }
};

function checkBadgeClass(status) {
  if (status === "FAILED") {
    return "border-rose-500/35 bg-rose-500/15 text-rose-300";
  }
  if (status === "FLAGGED") {
    return "border-amber-500/35 bg-amber-500/15 text-amber-300";
  }
  return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
}

export function VerdictPanel({
  phase,
  result,
  requestId,
  authError,
  isAuthorizing,
  onReset,
  onAuthorizeAndOpen
}) {
  const [copied, setCopied] = useState(false);
  const [confirmedRisk, setConfirmedRisk] = useState(false);
  const [showLayers, setShowLayers] = useState(false);

  if (phase === "checking" || phase === "opening") {
    return (
      <div
        className="flex min-h-[340px] flex-col items-center justify-center gap-5 py-8 text-center"
        aria-live="polite"
      >
        <div className="relative flex h-20 w-20 items-center justify-center rounded-2xl border border-rose-500/40 bg-rose-500/10 text-rose-400">
          <div className="absolute inset-0 animate-ping rounded-2xl border border-rose-500/30 opacity-40" />
          <ShieldCheck className="h-9 w-9" aria-hidden="true" />
        </div>
        <div className="space-y-1.5">
          <p className="text-xs font-bold uppercase tracking-[0.2em] text-rose-400">
            {phase === "opening" ? "Token Authorized" : "Inspecting On-Device"}
          </p>
          <h2 className="text-2xl font-extrabold text-white">
            {phase === "opening" ? "Opening Verified Destination..." : "Running 30 Security Layers..."}
          </h2>
          <p className="text-sm text-slate-400">
            Zero external calls made. Checking host, redirects, scripts, and scam lures.
          </p>
        </div>
        {requestId && (
          <div className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-xs text-slate-300">
            Request ID: {requestId}
          </div>
        )}
      </div>
    );
  }

  const meta = OUTCOME_META[phase] || OUTCOME_META.hold;
  const VerdictIcon = meta.icon;
  const riskSummary = result?.riskSummary || {};
  const securityChecks = result?.securityChecks || {};
  const redactedOrigin =
    result?.localVerification?.redactedDestination?.originOnly ||
    (result?.localVerification?.destination?.hostname
      ? `${result.localVerification.destination.protocol || "https:"}//${result.localVerification.destination.hostname}`
      : "Blocked / Redacted");
  const layersExecuted = Array.isArray(result?.layersExecuted) ? result.layersExecuted : [];
  const reasonCodes = Array.isArray(result?.finalReasonCodes) ? result.finalReasonCodes : [];
  const indicators = Array.isArray(result?.localVerification?.indicators)
    ? result.localVerification.indicators
    : [];

  const copyId = async () => {
    if (!requestId) return;
    try {
      await navigator.clipboard.writeText(requestId);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  const needsExplicitConfirmation = phase === "hold" || phase === "suspicious";

  return (
    <div className="space-y-5" aria-live="polite" data-testid="verdict-panel">
      {/* Primary Verdict Header */}
      <div className={`rounded-2xl border p-5 ${meta.border} ${meta.bg}`}>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-3.5">
            <div className={`mt-0.5 flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border ${meta.border} bg-[#0b0e14] ${meta.accentText}`}>
              <VerdictIcon className="h-6 w-6" aria-hidden="true" />
            </div>
            <div>
              <span className={`inline-flex rounded-md border px-2 py-0.5 font-mono text-[11px] font-bold tracking-wider ${meta.badgeBg}`}>
                {meta.badge}
              </span>
              <h2 className="mt-2 text-xl font-extrabold text-white sm:text-2xl">
                {riskSummary.headline ||
                  (phase === "invalid" ? "Invalid or unsupported URL" : "Verification complete")}
              </h2>
              <p className="mt-1 text-sm leading-relaxed text-slate-200">
                {riskSummary.parentAdvisory ||
                  (phase === "invalid"
                    ? "SafeGate only verifies valid HTTP or HTTPS web links without embedded credentials."
                    : "")}
              </p>
            </div>
          </div>

          {typeof riskSummary.score === "number" && (
            <div className="shrink-0 rounded-xl border border-white/10 bg-[#0b0e14]/80 px-3.5 py-2 text-left sm:text-right">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                Risk Score
              </div>
              <div className={`font-mono text-xl font-bold ${meta.accentText}`}>
                {riskSummary.score}
                <span className="text-xs font-normal text-slate-400"> / 10+</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Redacted Origin + Privacy Proof */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3.5">
          <div className="flex items-center justify-between gap-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            <span className="whitespace-nowrap">Origin Only</span>
            <span className="inline-flex items-center gap-1 whitespace-nowrap text-emerald-400">
              <Lock className="h-3 w-3 shrink-0" aria-hidden="true" />
              Secrets Stripped
            </span>
          </div>
          <div className="mt-1.5 truncate font-mono text-sm font-medium text-white">
            {redactedOrigin}
          </div>
        </div>

        <div className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-white/[0.03] p-3.5">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              <span className="whitespace-nowrap">Request ID</span>
              <span className="whitespace-nowrap text-emerald-400">0 Egress</span>
            </div>
            <div className="mt-1.5 truncate font-mono text-xs text-slate-200">
              {requestId}
            </div>
          </div>
          <button
            type="button"
            onClick={copyId}
            aria-label="Copy request ID"
            className="inline-flex min-h-[40px] min-w-[40px] shrink-0 cursor-pointer items-center justify-center rounded-lg border border-white/10 bg-white/5 px-2.5 text-xs font-semibold text-slate-200 transition hover:bg-white/10"
          >
            {copied ? (
              <Check className="h-4 w-4 text-emerald-400" aria-hidden="true" />
            ) : (
              <Copy className="h-4 w-4" aria-hidden="true" />
            )}
          </button>
        </div>
      </div>

      {/* Reason Codes */}
      {reasonCodes.length > 0 && (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3.5">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Findings & Reason Codes
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {reasonCodes.map((code) => (
              <span
                key={code}
                className="rounded-md border border-white/15 bg-white/5 px-2 py-1 font-mono text-[11px] text-slate-200"
              >
                {code}
              </span>
            ))}
            {indicators
              .filter((ind) => !reasonCodes.includes(ind))
              .slice(0, 6)
              .map((ind) => (
                <span
                  key={ind}
                  className="rounded-md border border-amber-500/25 bg-amber-500/10 px-2 py-1 font-mono text-[11px] text-amber-200"
                >
                  {ind}
                </span>
              ))}
          </div>
        </div>
      )}

      {/* 6 Security Domain Checks */}
      {Object.keys(securityChecks).length > 0 && (
        <div>
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Protection Domain Audit
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {CHECK_LABELS.map(({ key, label }) => {
              const status = securityChecks[key] || "PASSED";
              return (
                <div
                  key={key}
                  className="flex items-center justify-between gap-2 rounded-xl border border-white/10 bg-white/[0.02] px-3 py-2.5"
                >
                  <span className="text-xs font-medium text-slate-200">{label}</span>
                  <span
                    className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold ${checkBadgeClass(status)}`}
                  >
                    {status}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Confirmation Gate for HOLD / SUSPICIOUS */}
      {needsExplicitConfirmation && (
        <label className="flex min-h-[48px] cursor-pointer items-start gap-3 rounded-xl border border-amber-500/35 bg-amber-500/10 p-3.5 text-sm text-amber-100">
          <input
            type="checkbox"
            checked={confirmedRisk}
            onChange={(e) => setConfirmedRisk(e.target.checked)}
            className="mt-0.5 h-5 w-5 shrink-0 cursor-pointer accent-amber-500"
          />
          <span>
            I personally recognize the sender of this link and confirm I want SafeGate to issue a single-use redirect authorization token.
          </span>
        </label>
      )}

      {authError && (
        <p role="alert" className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-3 py-2 text-xs font-medium text-rose-300">
          {authError}
        </p>
      )}

      {/* Strict Policy Actions */}
      <div className="flex flex-wrap items-center gap-3 pt-1">
        {phase === "safe" && (
          <button
            type="button"
            disabled={isAuthorizing}
            onClick={() => onAuthorizeAndOpen(false)}
            className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl bg-emerald-600 px-5 text-sm font-bold text-white transition hover:bg-emerald-500 disabled:opacity-50 sm:flex-initial"
          >
            <ExternalLink className="h-4 w-4" aria-hidden="true" />
            <span>{isAuthorizing ? "Authorizing..." : "Open Verified Link"}</span>
          </button>
        )}

        {needsExplicitConfirmation && (
          <button
            type="button"
            disabled={!confirmedRisk || isAuthorizing}
            onClick={() => onAuthorizeAndOpen(true)}
            className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-amber-500/50 bg-amber-500/20 px-5 text-sm font-bold text-amber-200 transition hover:bg-amber-500/30 disabled:cursor-not-allowed disabled:opacity-40 sm:flex-initial"
          >
            <ExternalLink className="h-4 w-4" aria-hidden="true" />
            <span>{isAuthorizing ? "Authorizing..." : "Authorize & Open Anyway"}</span>
          </button>
        )}

        <button
          type="button"
          onClick={onReset}
          className="inline-flex min-h-[48px] flex-1 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-white/15 bg-white/5 px-5 text-sm font-semibold text-white transition hover:bg-white/10 sm:flex-initial"
        >
          <RotateCcw className="h-4 w-4" aria-hidden="true" />
          <span>{phase === "blocked" ? "Done — Scan Another Link" : "Scan Another Link"}</span>
        </button>

        {layersExecuted.length > 0 && (
          <button
            type="button"
            aria-expanded={showLayers}
            onClick={() => setShowLayers((prev) => !prev)}
            className="ml-auto inline-flex min-h-[44px] cursor-pointer items-center gap-1.5 rounded-xl px-3 text-xs font-semibold text-slate-400 transition hover:bg-white/5 hover:text-slate-200"
          >
            <span>{layersExecuted.length} Layers Executed</span>
            {showLayers ? (
              <ChevronUp className="h-4 w-4" aria-hidden="true" />
            ) : (
              <ChevronDown className="h-4 w-4" aria-hidden="true" />
            )}
          </button>
        )}
      </div>

      {showLayers && layersExecuted.length > 0 && (
        <div className="rounded-xl border border-white/10 bg-[#0b0e14] p-4">
          <div className="mb-2.5 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Execution Trace ({layersExecuted.length} On-Device Layers)
          </div>
          <ol className="grid grid-cols-1 gap-1.5 font-mono text-[11px] text-slate-300 sm:grid-cols-2">
            {layersExecuted.map((layer, index) => (
              <li key={layer} className="truncate">
                <span className="mr-2 text-slate-500">{String(index + 1).padStart(2, "0")}.</span>
                {layer}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
