import { useState } from 'react';
import { Smartphone, ArrowUpRight, RefreshCw } from 'lucide-react';
import { formatEventTime } from '../utils/insights.js';
import {
  AnimatedNumber,
  MiniSparkline,
  TimelineAreaChart,
  VerdictDonutChart,
  RiskDistributionChart,
  SecurityChecksChart
} from './InteractiveCharts.jsx';

const TIME_RANGES = [
  { id: 'ALL', label: 'All Time' },
  { id: '24H', label: 'Last 24h' },
  { id: '7D', label: 'Last 7d' },
  { id: '30D', label: 'Last 30d' }
];

export function InsightsView({
  insights,
  totalStoredCount = 0,
  range = 'ALL',
  onRangeChange,
  scopeDeviceId = 'ALL',
  onScopeDeviceChange,
  loading,
  onDrillDownDecision,
  onDrillDownDevice,
  onDrillDownRiskBand,
  onDrillDownDomain,
  onRefresh
}) {
  const [rightCardMode, setRightCardMode] = useState('indicators'); // 'indicators' | 'domains'

  if (loading && totalStoredCount === 0) {
    return (
      <div className="space-y-6" aria-busy="true">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="h-32 animate-pulse rounded-xl border border-slate-200 bg-white" />
          ))}
        </div>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="h-80 animate-pulse rounded-xl border border-slate-200 bg-white lg:col-span-8" />
          <div className="h-80 animate-pulse rounded-xl border border-slate-200 bg-white lg:col-span-4" />
        </div>
      </div>
    );
  }

  if (totalStoredCount === 0) {
    return (
      <div className="sg-animate-enter flex flex-col items-center justify-center rounded-2xl border border-slate-200/90 bg-white px-6 py-16 text-center shadow-[0_1px_3px_rgba(15,23,42,0.04)]">
        <h2 className="font-display text-lg font-semibold text-slate-900">No security events recorded yet</h2>
        <p className="mt-2 max-w-md text-sm text-slate-500">
          When devices running SafeGate inspect links, interactive threat graphs, device model analytics, and verification insights appear here automatically.
        </p>
        <button
          type="button"
          onClick={onRefresh}
          className="mt-6 inline-flex h-10 cursor-pointer items-center gap-2 rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 whitespace-nowrap"
        >
          <RefreshCw className="h-4 w-4" aria-hidden="true" />
          <span>Check for Events</span>
        </button>
      </div>
    );
  }

  const kpis = [
    {
      id: 'total',
      label: 'Total Inspected Events',
      value: insights.total,
      sub: `Avg score ${insights.avgScore} · ${insights.zeroEgressRate}% zero-egress`,
      tone: 'text-slate-900',
      stroke: '#2563EB',
      spark: insights.sparklines.total,
      decision: 'ALL'
    },
    {
      id: 'blocked',
      label: 'Blocked Threats',
      value: insights.blocked,
      sub: `${insights.total ? Math.round((insights.blocked / insights.total) * 100) : 0}% block ratio`,
      tone: 'text-rose-600',
      stroke: '#E11D48',
      spark: insights.sparklines.blocked,
      decision: 'BLOCK'
    },
    {
      id: 'queue',
      label: 'Open Review Queue',
      value: insights.openQueue,
      sub: `${insights.hold} held · ${insights.suspicious} suspicious`,
      tone: 'text-amber-600',
      stroke: '#D97706',
      spark: insights.sparklines.queue,
      decision: 'HOLD'
    },
    {
      id: 'devices',
      label: 'Active Devices',
      value: insights.uniqueDevices,
      sub: `${insights.resolvedCount} operator resolved`,
      tone: 'text-emerald-600',
      stroke: '#059669',
      spark: insights.sparklines.safe,
      decision: 'SAFE'
    }
  ];

  const maxReasonCount = Math.max(1, ...insights.topReasons.map((r) => r.count));
  const maxIndicatorCount = Math.max(1, ...insights.topIndicators.map((i) => i.count));
  const maxDomainCount = Math.max(1, ...(insights.topDomains || []).map((d) => d.count));

  return (
    <div className="space-y-6">
      {/* Interactive Scope Controls */}
      <div className="sg-animate-enter flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200/90 bg-white px-4 py-3 shadow-[0_1px_2px_rgba(15,23,42,0.03)]">
        <div className="inline-flex flex-wrap gap-1 rounded-lg bg-slate-100 p-1">
          {TIME_RANGES.map((opt) => {
            const active = range === opt.id;
            return (
              <button
                key={opt.id}
                type="button"
                onClick={() => onRangeChange?.(opt.id)}
                className={`cursor-pointer rounded-md px-3 py-1.5 text-xs font-medium transition-all whitespace-nowrap ${
                  active
                    ? 'bg-white text-blue-700 font-semibold shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {opt.label}
              </button>
            );
          })}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <label htmlFor="insights-device-scope" className="text-xs font-medium text-slate-500">
            Device scope
          </label>
          <select
            id="insights-device-scope"
            value={scopeDeviceId}
            onChange={(e) => onScopeDeviceChange?.(e.target.value)}
            className="h-9 cursor-pointer rounded-lg border border-slate-200 bg-white px-3 text-xs font-medium text-slate-800 outline-none transition focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
          >
            <option value="ALL">All Devices ({insights.devices.length})</option>
            {insights.devices.map((dev) => (
              <option key={dev.deviceId} value={dev.deviceId}>
                {dev.deviceName} ({dev.total})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Animated KPI Strip with Sparklines */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {kpis.map((kpi, idx) => (
          <button
            key={kpi.id}
            type="button"
            onClick={() => onDrillDownDecision(kpi.decision)}
            style={{ animationDelay: `${idx * 45}ms` }}
            className="sg-animate-enter group flex cursor-pointer flex-col justify-between rounded-xl border border-slate-200/90 bg-white p-5 text-left shadow-[0_1px_3px_rgba(15,23,42,0.04)] transition-all duration-200 hover:-translate-y-0.5 hover:border-blue-300 hover:shadow-[0_10px_24px_-8px_rgba(15,23,42,0.08)]"
          >
            <div className="flex w-full items-center justify-between gap-2 text-xs font-medium text-slate-500">
              <span>{kpi.label}</span>
              <ArrowUpRight
                className="h-3.5 w-3.5 text-slate-400 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-blue-600"
                aria-hidden="true"
              />
            </div>

            <div className="mt-3 flex items-end justify-between gap-3">
              <div className={`font-mono text-3xl font-bold tracking-tight tabular-nums ${kpi.tone}`}>
                <AnimatedNumber value={kpi.value} />
              </div>
              <MiniSparkline id={kpi.id} data={kpi.spark} stroke={kpi.stroke} />
            </div>

            <div className="mt-2 truncate text-xs text-slate-500 tabular-nums">
              {kpi.sub}
            </div>
          </button>
        ))}
      </div>

      {/* Hero Graph Row: Interactive Timeline + Interactive Donut Ring */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="sg-animate-enter lg:col-span-8" style={{ animationDelay: '120ms' }}>
          <TimelineAreaChart
            dailySeries={insights.dailyActivity}
            hourlySeries={insights.hourlyActivity}
            onSelectDecision={onDrillDownDecision}
          />
        </div>

        <div className="sg-animate-enter lg:col-span-4" style={{ animationDelay: '160ms' }}>
          <VerdictDonutChart
            insights={insights}
            onSelectDecision={onDrillDownDecision}
          />
        </div>
      </div>

      {/* Risk Spectrum + Verification Layer Matrix */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="sg-animate-enter lg:col-span-5" style={{ animationDelay: '200ms' }}>
          <RiskDistributionChart
            riskBuckets={insights.riskBuckets}
            onSelectRiskBand={onDrillDownRiskBand}
          />
        </div>

        <div className="sg-animate-enter lg:col-span-7" style={{ animationDelay: '240ms' }}>
          <SecurityChecksChart checkBreakdown={insights.checkBreakdown} />
        </div>
      </div>

      {/* Bottom 3-Col Breakdown: Devices Stacked + Top Reasons + Indicators/Domains */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <section className="sg-animate-enter rounded-xl border border-slate-200/90 bg-white p-6 shadow-[0_1px_3px_rgba(15,23,42,0.04)] transition-shadow hover:shadow-[0_10px_24px_-8px_rgba(15,23,42,0.08)]">
          <div className="flex items-baseline justify-between gap-2">
            <h2 className="font-display text-sm font-semibold text-slate-900">Devices by Model Name</h2>
            <span className="font-mono text-xs font-medium text-slate-500 tabular-nums">
              {insights.devices.length} total
            </span>
          </div>

          <div className="mt-4 space-y-3">
            {insights.devices.map((dev) => {
              const totalDev = Math.max(1, dev.total);
              const blkPct = (dev.blocked / totalDev) * 100;
              const holdPct = ((dev.hold + dev.suspicious) / totalDev) * 100;
              const safePct = (dev.safe / totalDev) * 100;

              return (
                <button
                  key={dev.deviceId}
                  type="button"
                  onClick={() => onDrillDownDevice(dev.deviceId)}
                  className="block w-full cursor-pointer rounded-lg border border-slate-200/80 bg-[#F8FAFC] p-3 text-left transition hover:border-blue-300 hover:bg-blue-50/40"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex min-w-0 items-center gap-2.5">
                      <Smartphone className="h-4 w-4 shrink-0 text-blue-600" aria-hidden="true" />
                      <div className="min-w-0">
                        <div className="truncate text-sm font-semibold text-slate-900">
                          {dev.deviceName}
                        </div>
                        <div className="truncate font-mono text-[11px] text-slate-500">
                          {dev.deviceId}
                        </div>
                      </div>
                    </div>
                    <div className="shrink-0 text-right font-mono tabular-nums">
                      <div className="text-sm font-bold text-slate-900">{dev.total}</div>
                      <div className="text-[11px] font-medium text-rose-600">{dev.blocked} blocked</div>
                    </div>
                  </div>
                  <div className="mt-2.5 flex h-1.5 w-full overflow-hidden rounded-full bg-slate-200/80">
                    {blkPct > 0 && <div style={{ width: `${blkPct}%` }} className="sg-bar-grow-x bg-rose-600" />}
                    {holdPct > 0 && <div style={{ width: `${holdPct}%` }} className="sg-bar-grow-x bg-sky-500" />}
                    {safePct > 0 && <div style={{ width: `${safePct}%` }} className="sg-bar-grow-x bg-emerald-500" />}
                  </div>
                </button>
              );
            })}
          </div>
        </section>

        <section className="sg-animate-enter rounded-xl border border-slate-200/90 bg-white p-6 shadow-[0_1px_3px_rgba(15,23,42,0.04)] transition-shadow hover:shadow-[0_10px_24px_-8px_rgba(15,23,42,0.08)]">
          <h2 className="font-display text-sm font-semibold text-slate-900">Top Verdict Reasons</h2>
          {insights.topReasons.length === 0 ? (
            <p className="mt-6 text-xs text-slate-500">No reason codes logged in this filter.</p>
          ) : (
            <div className="mt-4 space-y-3.5">
              {insights.topReasons.map((item) => {
                const widthPct = Math.max(8, Math.round((item.count / maxReasonCount) * 100));
                return (
                  <div key={item.code}>
                    <div className="flex items-center justify-between gap-3 text-xs">
                      <span className="truncate font-mono text-slate-700">{item.code}</span>
                      <span className="shrink-0 font-mono font-semibold text-slate-900 tabular-nums">
                        {item.count}
                      </span>
                    </div>
                    <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                      <div
                        style={{ width: `${widthPct}%` }}
                        className="sg-bar-grow-x h-full rounded-full bg-amber-500"
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="sg-animate-enter flex flex-col justify-between rounded-xl border border-slate-200/90 bg-white p-6 shadow-[0_1px_3px_rgba(15,23,42,0.04)] transition-shadow hover:shadow-[0_10px_24px_-8px_rgba(15,23,42,0.08)]">
          <div>
            <div className="flex items-center justify-between gap-2">
              <h2 className="font-display text-sm font-semibold text-slate-900">
                {rightCardMode === 'domains' ? 'Top Targeted Hosts' : 'Top Threat Indicators'}
              </h2>
              <div className="inline-flex rounded-lg bg-slate-100 p-0.5 text-[11px]">
                <button
                  type="button"
                  onClick={() => setRightCardMode('indicators')}
                  className={`cursor-pointer rounded-md px-2 py-1 font-medium transition whitespace-nowrap ${
                    rightCardMode === 'indicators'
                      ? 'bg-white text-slate-900 shadow-sm'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Indicators
                </button>
                <button
                  type="button"
                  onClick={() => setRightCardMode('domains')}
                  className={`cursor-pointer rounded-md px-2 py-1 font-medium transition whitespace-nowrap ${
                    rightCardMode === 'domains'
                      ? 'bg-white text-slate-900 shadow-sm'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Domains
                </button>
              </div>
            </div>

            {rightCardMode === 'indicators' ? (
              insights.topIndicators.length === 0 ? (
                <p className="mt-6 text-xs text-slate-500">No threat indicators triggered in this filter.</p>
              ) : (
                <div className="mt-4 space-y-3.5">
                  {insights.topIndicators.map((item) => {
                    const widthPct = Math.max(8, Math.round((item.count / maxIndicatorCount) * 100));
                    return (
                      <div key={item.code}>
                        <div className="flex items-center justify-between gap-3 text-xs">
                          <span className="truncate font-mono text-slate-700">{item.code}</span>
                          <span className="shrink-0 font-mono font-semibold text-slate-900 tabular-nums">
                            {item.count}
                          </span>
                        </div>
                        <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                          <div
                            style={{ width: `${widthPct}%` }}
                            className="sg-bar-grow-x h-full rounded-full bg-rose-500"
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )
            ) : !insights.topDomains || insights.topDomains.length === 0 ? (
              <p className="mt-6 text-xs text-slate-500">No host domains recorded in this filter.</p>
            ) : (
              <div className="mt-4 space-y-3">
                {insights.topDomains.map((item) => {
                  const widthPct = Math.max(8, Math.round((item.count / maxDomainCount) * 100));
                  return (
                    <button
                      key={item.domain}
                      type="button"
                      onClick={() => onDrillDownDomain?.(item.domain)}
                      className="block w-full cursor-pointer text-left group"
                    >
                      <div className="flex items-center justify-between gap-3 text-xs">
                        <span className="truncate font-mono text-slate-700 group-hover:text-blue-700">
                          {item.domain}
                        </span>
                        <span className="shrink-0 font-mono font-semibold text-slate-900 tabular-nums">
                          {item.count}
                        </span>
                      </div>
                      <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                        <div
                          style={{ width: `${widthPct}%` }}
                          className="sg-bar-grow-x h-full rounded-full bg-blue-600"
                        />
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {insights.devices[0]?.lastSeenAt && (
            <div className="mt-6 border-t border-slate-100 pt-3 text-xs text-slate-500 tabular-nums">
              Latest scan · {formatEventTime(insights.devices[0].lastSeenAt)}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
