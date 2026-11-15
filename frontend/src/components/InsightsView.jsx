import { Smartphone, ArrowUpRight, RefreshCw } from 'lucide-react';
import { formatEventTime } from '../utils/insights.js';

export function InsightsView({
  insights,
  loading,
  onDrillDownDecision,
  onDrillDownDevice,
  onRefresh
}) {
  if (loading && insights.total === 0) {
    return (
      <div className="space-y-6" aria-busy="true">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="h-28 animate-pulse rounded-xl border border-white/[0.06] bg-[#101624]" />
          ))}
        </div>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="h-72 animate-pulse rounded-xl border border-white/[0.06] bg-[#101624]" />
          <div className="h-72 animate-pulse rounded-xl border border-white/[0.06] bg-[#101624]" />
        </div>
      </div>
    );
  }

  if (insights.total === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-2xl border border-white/[0.08] bg-[#101624] px-6 py-16 text-center">
        <h2 className="text-lg font-semibold text-slate-100">No security events recorded yet</h2>
        <p className="mt-2 max-w-md text-sm text-slate-400">
          When devices running SafeGate inspect links, threat verdicts, device model names, and protection insights appear here automatically.
        </p>
        <button
          type="button"
          onClick={onRefresh}
          className="mt-6 inline-flex h-10 cursor-pointer items-center gap-2 rounded-lg bg-sky-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 whitespace-nowrap"
        >
          <RefreshCw className="h-4 w-4" aria-hidden="true" />
          <span>Check for Events</span>
        </button>
      </div>
    );
  }

  const kpis = [
    {
      label: 'Total Inspected Events',
      value: insights.total,
      sub: `Avg risk score ${insights.avgScore} · ${insights.zeroEgressRate}% zero-egress`,
      tone: 'text-slate-50',
      decision: 'ALL'
    },
    {
      label: 'Blocked Threats',
      value: insights.blocked,
      sub: `${insights.total ? Math.round((insights.blocked / insights.total) * 100) : 0}% of total traffic`,
      tone: 'text-rose-400',
      decision: 'BLOCK'
    },
    {
      label: 'Open Review Queue',
      value: insights.openQueue,
      sub: `${insights.hold} held · ${insights.suspicious} suspicious`,
      tone: 'text-amber-300',
      decision: 'HOLD'
    },
    {
      label: 'Active Devices',
      value: insights.uniqueDevices,
      sub: `${insights.resolvedCount} operator resolved`,
      tone: 'text-emerald-400',
      decision: 'SAFE'
    }
  ];

  const decisionMix = [
    { id: 'BLOCK', label: 'Blocked', count: insights.blocked, color: 'bg-rose-500', text: 'text-rose-400' },
    { id: 'SUSPICIOUS', label: 'Suspicious', count: insights.suspicious, color: 'bg-amber-400', text: 'text-amber-400' },
    { id: 'HOLD', label: 'Hold', count: insights.hold, color: 'bg-sky-400', text: 'text-sky-400' },
    { id: 'SAFE', label: 'Safe / Cleared', count: insights.safe, color: 'bg-emerald-400', text: 'text-emerald-400' }
  ];

  const maxDayTotal = Math.max(1, ...insights.dailyActivity.map((d) => d.total));
  const maxReasonCount = Math.max(1, ...insights.topReasons.map((r) => r.count));
  const maxIndicatorCount = Math.max(1, ...insights.topIndicators.map((i) => i.count));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {kpis.map((kpi) => (
          <button
            key={kpi.label}
            type="button"
            onClick={() => onDrillDownDecision(kpi.decision)}
            className="flex cursor-pointer flex-col justify-between rounded-xl border border-white/[0.08] bg-[#101624] p-5 text-left transition-colors hover:border-white/[0.16]"
          >
            <div className="flex w-full items-center justify-between gap-2 text-xs font-medium text-slate-400">
              <span>{kpi.label}</span>
              <ArrowUpRight className="h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
            </div>
            <div className={`mt-3 font-mono text-3xl font-semibold tracking-tight tabular-nums ${kpi.tone}`}>
              {kpi.value}
            </div>
            <div className="mt-2 truncate text-xs text-slate-500 tabular-nums">
              {kpi.sub}
            </div>
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section className="rounded-xl border border-white/[0.08] bg-[#101624] p-6">
          <div className="flex items-baseline justify-between gap-4">
            <h2 className="text-sm font-semibold text-slate-100">Verdict Distribution</h2>
            <span className="font-mono text-xs text-slate-400 tabular-nums">
              {insights.total} events
            </span>
          </div>

          <div className="mt-5 flex h-3 w-full overflow-hidden rounded-full bg-white/[0.06]">
            {decisionMix.map((seg) => {
              const pct = insights.total > 0 ? (seg.count / insights.total) * 100 : 0;
              if (pct <= 0) return null;
              return (
                <div
                  key={seg.id}
                  style={{ width: `${pct}%` }}
                  className={`${seg.color} h-full transition-all`}
                  title={`${seg.label}: ${seg.count}`}
                />
              );
            })}
          </div>

          <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {decisionMix.map((seg) => {
              const pct = insights.total > 0 ? Math.round((seg.count / insights.total) * 100) : 0;
              return (
                <button
                  key={seg.id}
                  type="button"
                  onClick={() => onDrillDownDecision(seg.id)}
                  className="cursor-pointer rounded-lg border border-white/[0.06] bg-[#0B101B] p-3 text-left transition-colors hover:border-white/[0.14]"
                >
                  <div className={`text-xs font-medium ${seg.text}`}>{seg.label}</div>
                  <div className="mt-1.5 font-mono text-xl font-semibold text-slate-100 tabular-nums">
                    {seg.count}
                  </div>
                  <div className="mt-0.5 font-mono text-[11px] text-slate-500 tabular-nums">
                    {pct}%
                  </div>
                </button>
              );
            })}
          </div>
        </section>

        <section className="rounded-xl border border-white/[0.08] bg-[#101624] p-6">
          <div className="flex items-baseline justify-between gap-4">
            <h2 className="text-sm font-semibold text-slate-100">Daily Scan &amp; Block Activity</h2>
            <span className="text-xs text-slate-500">UTC date buckets</span>
          </div>

          {insights.dailyActivity.length === 0 ? (
            <p className="mt-10 text-center text-xs text-slate-500">No dated events available.</p>
          ) : (
            <div className="mt-6 flex h-40 items-end gap-2 border-b border-white/[0.07] pb-3">
              {insights.dailyActivity.map((day) => {
                const totalHeightPct = Math.max(8, Math.round((day.total / maxDayTotal) * 100));
                const blockedRatioPct = day.total > 0 ? Math.round((day.blocked / day.total) * 100) : 0;
                return (
                  <div
                    key={day.day}
                    className="flex h-full flex-1 flex-col items-center justify-end gap-1.5"
                    title={`${day.day}: ${day.total} total (${day.blocked} blocked)`}
                  >
                    <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                      {day.total}
                    </span>
                    <div
                      style={{ height: `${totalHeightPct}%` }}
                      className="relative flex w-full max-w-[36px] flex-col justify-end overflow-hidden rounded-t-md bg-sky-500/35"
                    >
                      {blockedRatioPct > 0 && (
                        <div
                          style={{ height: `${blockedRatioPct}%` }}
                          className="w-full bg-rose-500/80"
                        />
                      )}
                    </div>
                    <span className="font-mono text-[10px] text-slate-500 tabular-nums">
                      {day.day.slice(5)}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <section className="rounded-xl border border-white/[0.08] bg-[#101624] p-6">
          <div className="flex items-baseline justify-between gap-2">
            <h2 className="text-sm font-semibold text-slate-100">Devices by Model Name</h2>
            <span className="font-mono text-xs text-slate-500 tabular-nums">
              {insights.devices.length} total
            </span>
          </div>

          <div className="mt-4 divide-y divide-white/[0.06]">
            {insights.devices.map((dev) => (
              <button
                key={dev.deviceId}
                type="button"
                onClick={() => onDrillDownDevice(dev.deviceId)}
                className="flex w-full cursor-pointer items-center justify-between gap-3 py-3 text-left transition-colors hover:bg-white/[0.02]"
              >
                <div className="flex min-w-0 items-center gap-3">
                  <Smartphone className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium text-slate-100">
                      {dev.deviceName}
                    </div>
                    <div className="truncate font-mono text-[11px] text-slate-500">
                      {dev.deviceId}
                    </div>
                  </div>
                </div>
                <div className="shrink-0 text-right font-mono tabular-nums">
                  <div className="text-sm font-semibold text-slate-100">{dev.total}</div>
                  <div className="text-[11px] text-rose-400">
                    {dev.blocked} blocked
                  </div>
                </div>
              </button>
            ))}
          </div>
        </section>

        <section className="rounded-xl border border-white/[0.08] bg-[#101624] p-6">
          <h2 className="text-sm font-semibold text-slate-100">Top Verdict Reasons</h2>
          {insights.topReasons.length === 0 ? (
            <p className="mt-6 text-xs text-slate-500">No reason codes logged yet.</p>
          ) : (
            <div className="mt-4 space-y-3.5">
              {insights.topReasons.map((item) => {
                const widthPct = Math.max(6, Math.round((item.count / maxReasonCount) * 100));
                return (
                  <div key={item.code}>
                    <div className="flex items-center justify-between gap-3 text-xs">
                      <span className="truncate font-mono text-slate-300">{item.code}</span>
                      <span className="shrink-0 font-mono font-semibold text-slate-100 tabular-nums">
                        {item.count}
                      </span>
                    </div>
                    <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]">
                      <div style={{ width: `${widthPct}%` }} className="h-full rounded-full bg-amber-400/80" />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="rounded-xl border border-white/[0.08] bg-[#101624] p-6">
          <h2 className="text-sm font-semibold text-slate-100">Top Threat Indicators</h2>
          {insights.topIndicators.length === 0 ? (
            <p className="mt-6 text-xs text-slate-500">No threat indicators triggered.</p>
          ) : (
            <div className="mt-4 space-y-3.5">
              {insights.topIndicators.map((item) => {
                const widthPct = Math.max(6, Math.round((item.count / maxIndicatorCount) * 100));
                return (
                  <div key={item.code}>
                    <div className="flex items-center justify-between gap-3 text-xs">
                      <span className="truncate font-mono text-slate-300">{item.code}</span>
                      <span className="shrink-0 font-mono font-semibold text-slate-100 tabular-nums">
                        {item.count}
                      </span>
                    </div>
                    <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]">
                      <div style={{ width: `${widthPct}%` }} className="h-full rounded-full bg-rose-400/80" />
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {insights.devices[0]?.lastSeenAt && (
            <div className="mt-6 border-t border-white/[0.07] pt-3 text-xs text-slate-500 tabular-nums">
              Latest scan · {formatEventTime(insights.devices[0].lastSeenAt)}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
