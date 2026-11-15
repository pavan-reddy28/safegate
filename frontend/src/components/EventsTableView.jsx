import { Search, Download, CheckCircle2, ShieldBan, Eye } from 'lucide-react';
import {
  formatEventTime,
  getDecisionStyle,
  getStatusLabel,
  exportEventsToCsv
} from '../utils/insights.js';

const DECISION_TABS = [
  { id: 'ALL', label: 'All' },
  { id: 'BLOCK', label: 'Blocked' },
  { id: 'HOLD', label: 'Hold' },
  { id: 'SUSPICIOUS', label: 'Suspicious' },
  { id: 'SAFE', label: 'Safe' }
];

const STATUS_TABS = [
  { id: 'ALL', label: 'Any Status' },
  { id: 'OPEN', label: 'Open' },
  { id: 'REVIEWED', label: 'Reviewed' },
  { id: 'RESOLVED', label: 'Resolved' },
  { id: 'ARCHIVED', label: 'Archived' }
];

const RISK_BANDS = [
  { id: 'ALL', label: 'Any Score' },
  { id: '75-100', label: 'Score 75–100 (Critical)' },
  { id: '50-74', label: 'Score 50–74 (Elevated)' },
  { id: '21-49', label: 'Score 21–49 (Moderate)' },
  { id: '0-20', label: 'Score 0–20 (Low)' }
];

export function EventsTableView({
  events,
  devices,
  loading,
  search,
  onSearchChange,
  decisionFilter,
  onDecisionFilterChange,
  statusFilter,
  onStatusFilterChange,
  deviceFilter,
  onDeviceFilterChange,
  riskBandFilter = 'ALL',
  onRiskBandFilterChange,
  onOpenDetail,
  onQuickAction,
  busyRequestId
}) {
  const handleDownloadCsv = () => {
    const csv = exportEventsToCsv(events);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `safegate-events-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="sg-animate-enter space-y-4">
      <div className="flex flex-col gap-3 rounded-xl border border-white/[0.08] bg-[#101624] p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="relative flex-1">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"
              aria-hidden="true"
            />
            <label htmlFor="events-search-input" className="sr-only">
              Search events by request ID, device name, host, or reason
            </label>
            <input
              id="events-search-input"
              type="search"
              value={search}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search requestId, Vivo V2355, host, reason code..."
              className="h-10 w-full rounded-lg border border-white/[0.1] bg-[#0B101B] pl-9 pr-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-sky-400/70"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <label htmlFor="device-filter-select" className="sr-only">
              Filter by phone device
            </label>
            <select
              id="device-filter-select"
              value={deviceFilter}
              onChange={(e) => onDeviceFilterChange(e.target.value)}
              className="h-10 cursor-pointer rounded-lg border border-white/[0.1] bg-[#0B101B] px-3 text-xs font-medium text-slate-200 outline-none focus:border-sky-400/70"
            >
              <option value="ALL">All Devices ({devices.length})</option>
              {devices.map((dev) => (
                <option key={dev.deviceId} value={dev.deviceId}>
                  {dev.deviceName} ({dev.total})
                </option>
              ))}
            </select>

            <label htmlFor="status-filter-select" className="sr-only">
              Filter by review status
            </label>
            <select
              id="status-filter-select"
              value={statusFilter}
              onChange={(e) => onStatusFilterChange(e.target.value)}
              className="h-10 cursor-pointer rounded-lg border border-white/[0.1] bg-[#0B101B] px-3 text-xs font-medium text-slate-200 outline-none focus:border-sky-400/70"
            >
              {STATUS_TABS.map((tab) => (
                <option key={tab.id} value={tab.id}>
                  {tab.label}
                </option>
              ))}
            </select>

            <label htmlFor="risk-band-filter-select" className="sr-only">
              Filter by risk score band
            </label>
            <select
              id="risk-band-filter-select"
              value={riskBandFilter}
              onChange={(e) => onRiskBandFilterChange?.(e.target.value)}
              className="h-10 cursor-pointer rounded-lg border border-white/[0.1] bg-[#0B101B] px-3 text-xs font-medium text-slate-200 outline-none focus:border-sky-400/70"
            >
              {RISK_BANDS.map((band) => (
                <option key={band.id} value={band.id}>
                  {band.label}
                </option>
              ))}
            </select>

            <button
              type="button"
              onClick={handleDownloadCsv}
              disabled={events.length === 0}
              className="inline-flex h-10 cursor-pointer items-center gap-1.5 rounded-lg border border-white/[0.1] bg-white/[0.04] px-3.5 text-xs font-medium text-slate-200 transition hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-40 whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] pt-3">
          <div className="inline-flex flex-wrap gap-1 rounded-lg bg-[#0B101B] p-1">
            {DECISION_TABS.map((tab) => {
              const active = decisionFilter === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => onDecisionFilterChange(tab.id)}
                  className={`cursor-pointer rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    active
                      ? 'bg-white/[0.1] text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>

          <div className="font-mono text-xs text-slate-400 tabular-nums">
            Showing {events.length} {events.length === 1 ? 'event' : 'events'}
          </div>
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-[#101624]">
        {loading && events.length === 0 ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="h-11 animate-pulse rounded-lg bg-white/[0.04]" />
            ))}
          </div>
        ) : events.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <p className="text-sm font-medium text-slate-300">No events match your current filters</p>
            <p className="mt-1 text-xs text-slate-500">
              Try clearing the search query or switching verdict and device filters.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[880px] border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-white/[0.08] bg-[#0C111C] text-[11px] font-semibold text-slate-400">
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Device</th>
                  <th className="px-4 py-3">Verdict</th>
                  <th className="px-4 py-3 text-right">Score</th>
                  <th className="px-4 py-3">Host / Domain</th>
                  <th className="px-4 py-3">Primary Reason</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]">
                {events.map((ev) => {
                  const dec = getDecisionStyle(ev.decision);
                  const st = getStatusLabel(ev.status);
                  const isBusy = busyRequestId === ev.requestId;
                  const topReason = Array.isArray(ev.reasons) && ev.reasons.length > 0 ? ev.reasons[0] : '—';
                  const destLabel = ev.destinationHost || ev.registrableDomain || 'Redacted';

                  return (
                    <tr
                      key={ev.requestId}
                      onClick={() => onOpenDetail(ev)}
                      className="cursor-pointer transition-colors hover:bg-white/[0.03]"
                    >
                      <td className="px-4 py-3 font-mono text-slate-400 tabular-nums whitespace-nowrap">
                        {formatEventTime(ev.eventTime)}
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-slate-100 whitespace-nowrap">
                          {ev.deviceName || 'Unlabeled Device'}
                        </div>
                        <div className="max-w-[160px] truncate font-mono text-[11px] text-slate-500">
                          {ev.deviceId}
                        </div>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className={`font-semibold ${dec.textClass}`}>
                          {dec.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right font-mono font-semibold text-slate-200 tabular-nums whitespace-nowrap">
                        {ev.score}
                      </td>
                      <td className="px-4 py-3">
                        <div className="max-w-[180px] truncate font-mono text-slate-200">
                          {destLabel}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="max-w-[230px] truncate font-mono text-[11px] text-slate-300">
                          {topReason}
                        </div>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className={`font-medium ${st.textClass}`}>
                          {st.label}
                        </span>
                      </td>
                      <td
                        className="px-4 py-3 text-right whitespace-nowrap"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => onQuickAction(ev, 'ALLOW')}
                            title="Approve and allow opening"
                            aria-label={`Allow ${ev.requestId}`}
                            className="inline-flex h-7 cursor-pointer items-center gap-1 rounded-md border border-emerald-500/25 bg-emerald-500/10 px-2 text-[11px] font-medium text-emerald-300 transition hover:bg-emerald-500/20 disabled:opacity-50"
                          >
                            <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                            <span>Allow</span>
                          </button>
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => onQuickAction(ev, 'BLOCK')}
                            title="Enforce block"
                            aria-label={`Block ${ev.requestId}`}
                            className="inline-flex h-7 cursor-pointer items-center gap-1 rounded-md border border-rose-500/25 bg-rose-500/10 px-2 text-[11px] font-medium text-rose-300 transition hover:bg-rose-500/20 disabled:opacity-50"
                          >
                            <ShieldBan className="h-3 w-3" aria-hidden="true" />
                            <span>Block</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => onOpenDetail(ev)}
                            aria-label={`Inspect ${ev.requestId}`}
                            className="inline-flex h-7 cursor-pointer items-center gap-1 rounded-md border border-white/[0.1] bg-white/[0.04] px-2 text-[11px] font-medium text-slate-200 transition hover:bg-white/[0.08]"
                          >
                            <Eye className="h-3 w-3" aria-hidden="true" />
                            <span>Inspect</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
