import { useState } from "react";
import { ShieldAlert, ShieldCheck, Search, ClipboardPaste, X, Sparkles } from "lucide-react";

const TEST_PRESETS = [
  {
    id: "safe-bank",
    label: "Official SBI Bank",
    tag: "SAFE",
    tone: "emerald",
    url: "https://www.sbi.co.in/personal/banking?session=localdemo"
  },
  {
    id: "hold-domain",
    label: "Unverified Domain",
    tag: "HOLD",
    tone: "sky",
    url: "https://example.org/family/photo-album"
  },
  {
    id: "phish-test",
    label: "Google Test Phish",
    tag: "BLOCK",
    tone: "rose",
    url: "https://testsafebrowsing.appspot.com/s/phishing.html"
  },
  {
    id: "sms-scam",
    label: "Fake KYC SMS Scam",
    tag: "BLOCK",
    tone: "rose",
    url: "https://sbi-kyc-update.xyz/amount-credited/claim?otp=998877"
  },
  {
    id: "shortener",
    label: "URL Shortener",
    tag: "WARN",
    tone: "amber",
    url: "https://bit.ly/3xFakeBankSms"
  },
  {
    id: "rogue-apk",
    label: "Rogue APK Drop",
    tag: "BLOCK",
    tone: "rose",
    url: "http://rewards-claim.top/SBI_KYC_Update.apk"
  },
  {
    id: "upi-trap",
    label: "UPI Intent Redirect",
    tag: "BLOCK",
    tone: "rose",
    url: "https://example.org/claim?next=upi%3A%2F%2Fpay%3Fpa%3Dscammer%40upi%26am%3D15000"
  },
  {
    id: "homograph-spoof",
    label: "Cyrillic IDN Homograph",
    tag: "BLOCK",
    tone: "rose",
    url: "https://xn--bi-doc.co.in/login"
  }
];

const TONE_BADGE_CLASSES = {
  emerald: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  sky: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  amber: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  rose: "bg-rose-500/15 text-rose-300 border-rose-500/30"
};

export function ScannerPanel({ onScanUrl, isBusy, inputError }) {
  const [urlInput, setUrlInput] = useState("");

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!urlInput.trim() || isBusy) return;
    onScanUrl(urlInput.trim());
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrlInput(text.trim());
      }
    } catch {
      // Clipboard read permission declined cleanly
    }
  };

  const runPreset = (presetUrl) => {
    if (isBusy) return;
    setUrlInput(presetUrl);
    onScanUrl(presetUrl);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-widest text-rose-400">
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
            30-Layer On-Device Shield
          </span>
          <h1 className="mt-1.5 text-2xl font-extrabold tracking-tight text-white sm:text-3xl">
            Inspect any link before opening it
          </h1>
          <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-slate-400">
            Every check runs offline inside SafeGate. Sensitive query parameters, OTPs, and fragments are stripped and never leave this device.
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-3" noValidate>
        <label
          htmlFor="safegate-url-input"
          className="block text-xs font-semibold uppercase tracking-wider text-slate-300"
        >
          Destination URL to verify
        </label>

        <div className="flex flex-col gap-2.5 sm:flex-row sm:items-stretch">
          <div className="relative flex-1">
            <Search
              className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
              aria-hidden="true"
            />
            <input
              id="safegate-url-input"
              type="url"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              placeholder="https://example.com/verify-account"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              className="min-h-[48px] w-full rounded-xl border border-white/15 bg-[#0b0e14] pl-10 pr-20 font-mono text-sm text-white placeholder-slate-500 transition focus:border-rose-500 focus:outline-none focus:ring-2 focus:ring-rose-500/25"
            />
            <div className="absolute right-2 top-1/2 flex -translate-y-1/2 items-center gap-1">
              {urlInput ? (
                <button
                  type="button"
                  onClick={() => setUrlInput("")}
                  aria-label="Clear URL input"
                  className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 transition hover:bg-white/10 hover:text-white"
                >
                  <X className="h-4 w-4" aria-hidden="true" />
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handlePaste}
                  aria-label="Paste URL from clipboard"
                  className="inline-flex h-8 items-center gap-1 rounded-lg border border-white/10 bg-white/5 px-2.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 hover:text-white"
                >
                  <ClipboardPaste className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Paste</span>
                </button>
              )}
            </div>
          </div>

          <button
            type="submit"
            disabled={isBusy || !urlInput.trim()}
            className="inline-flex min-h-[48px] shrink-0 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl bg-rose-600 px-6 text-sm font-bold text-white shadow-sm transition hover:bg-rose-500 active:scale-[0.99] disabled:cursor-not-allowed disabled:opacity-45"
          >
            <ShieldAlert className="h-4 w-4" aria-hidden="true" />
            <span>{isBusy ? "Scanning..." : "Verify Link"}</span>
          </button>
        </div>

        {inputError && (
          <p role="alert" className="text-xs font-medium text-rose-400">
            {inputError}
          </p>
        )}
      </form>

      <div className="border-t border-white/10 pt-5">
        <div className="mb-3 flex items-center justify-between gap-2">
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400">
            <Sparkles className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
            Instant Threat Test Scenarios
          </span>
          <span className="text-xs text-slate-500">Tap any scenario to inspect</span>
        </div>

        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {TEST_PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              disabled={isBusy}
              onClick={() => runPreset(preset.url)}
              className="group flex min-h-[48px] cursor-pointer items-center justify-between gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-2.5 text-left transition hover:border-white/25 hover:bg-white/[0.06] disabled:cursor-not-allowed disabled:opacity-50"
            >
              <div className="min-w-0">
                <div className="truncate text-sm font-semibold text-slate-100">
                  {preset.label}
                </div>
                <div className="truncate font-mono text-[11px] text-slate-400">
                  {preset.url}
                </div>
              </div>
              <span
                className={`shrink-0 rounded-md border px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider ${TONE_BADGE_CLASSES[preset.tone]}`}
              >
                {preset.tag}
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
