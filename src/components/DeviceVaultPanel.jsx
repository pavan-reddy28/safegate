import { Database, Shield, Trash2, Lock, Cpu, EyeOff } from "lucide-react";

export function DeviceVaultPanel({
  vaultItems,
  isNative,
  onRemoveEntry,
  onClearVault
}) {
  return (
    <aside className="space-y-4">
      {/* Architecture & Zero-Egress Guarantee Card */}
      <section className="rounded-2xl border border-white/10 bg-[#12161f] p-5">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
            Zero-Egress Guarantees
          </h2>
          <span className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-300">
            OFFLINE READY
          </span>
        </div>

        <ul className="mt-4 space-y-3 text-xs leading-relaxed text-slate-300">
          <li className="flex items-start gap-2.5">
            <EyeOff className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
            <span>
              <strong className="font-semibold text-white">0 outbound requests:</strong> URLs are inspected strictly inside this device.
            </span>
          </li>
          <li className="flex items-start gap-2.5">
            <Cpu className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" aria-hidden="true" />
            <span>
              <strong className="font-semibold text-white">30 detection layers:</strong> Homographs, Damerau typosquats, UPI/Intent traps, rogue APKs, &amp; phishing kits.
            </span>
          </li>
          <li className="flex items-start gap-2.5">
            <Lock className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" aria-hidden="true" />
            <span>
              <strong className="font-semibold text-white">No URL retention:</strong> Only anonymous SHA-256 block fingerprints are persisted locally.
            </span>
          </li>
        </ul>
      </section>

      {/* Local Blocked Fingerprints Vault */}
      <section className="rounded-2xl border border-white/10 bg-[#12161f] p-5">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-rose-400" aria-hidden="true" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Device Block Vault
            </h2>
            <span
              data-testid="vault-count"
              className="rounded-full bg-white/10 px-2 py-0.5 font-mono text-xs font-bold text-white"
            >
              {vaultItems.length}
            </span>
          </div>

          {vaultItems.length > 0 && (
            <button
              type="button"
              onClick={onClearVault}
              className="inline-flex min-h-[36px] cursor-pointer items-center gap-1 rounded-lg border border-white/10 bg-white/5 px-2.5 text-xs font-semibold text-slate-300 transition hover:border-rose-500/40 hover:bg-rose-500/15 hover:text-rose-200"
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Clear All</span>
            </button>
          )}
        </div>

        <p className="mt-1.5 text-xs text-slate-400">
          {isNative
            ? "Backed by encrypted Android SQLCipher database."
            : "Backed by browser IndexedDB storage. Repeated threats block instantly."}
        </p>

        {vaultItems.length === 0 ? (
          <div className="mt-4 flex flex-col items-center justify-center rounded-xl border border-dashed border-white/10 bg-[#0b0e14]/70 px-4 py-7 text-center">
            <Shield className="h-7 w-7 text-slate-600" aria-hidden="true" />
            <p className="mt-2 text-xs font-semibold text-slate-300">
              No blocked threats recorded yet
            </p>
            <p className="mt-1 text-[11px] text-slate-500">
              Blocked URLs store an irreversible SHA-256 digest here so they stop immediately next time.
            </p>
          </div>
        ) : (
          <ul className="mt-3.5 max-h-[360px] space-y-2 overflow-y-auto pr-1" data-testid="vault-list">
            {vaultItems.map((entry) => {
              const primaryReason = entry.reasonCodes?.[0] || "SECURITY_BLOCK";
              const shortHash = `${entry.fingerprint.slice(0, 12)}…${entry.fingerprint.slice(-6)}`;
              return (
                <li
                  key={entry.fingerprint}
                  className="flex items-start justify-between gap-2.5 rounded-xl border border-rose-500/25 bg-rose-500/[0.06] p-3"
                >
                  <div className="min-w-0 space-y-1">
                    <div className="truncate text-xs font-bold text-rose-200">
                      {entry.originHost || "Blocked Origin"}
                    </div>
                    <div className="truncate font-mono text-[10px] text-slate-300">
                      {primaryReason}
                    </div>
                    <div className="font-mono text-[10px] text-slate-500">
                      SHA256: {shortHash}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => onRemoveEntry(entry.fingerprint)}
                    aria-label={`Remove blocked entry ${entry.originHost || shortHash}`}
                    className="flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-white/10 bg-white/5 text-slate-400 transition hover:border-rose-500/40 hover:bg-rose-500/20 hover:text-rose-200"
                  >
                    <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </aside>
  );
}
