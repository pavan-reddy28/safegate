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
      <div className="flex flex-col gap-3 rounded-xl border border-slate-200/90 bg-white p-4 shadow-[0_1px_3px_rgba(15,23,42,0.04)]">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="relative flex-1">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
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
              className="h-10 w-full rounded-lg border border-slate-200 bg-[#F8FAFC] pl-9 pr-3 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:ring-2 focus:ring-blue-600/15"
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
              className="h-10 cursor-pointer rounded-lg border border-slate-200 bg-white px-3 text-xs font-medium text-slate-800 outline-none transition focus:border-blue-600"
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
              className="h-10 cursor-pointer rounded-lg border border-slate-200 bg-white px-3 text-xs font-medium text-slate-800 outline-none transition focus:border-blue-600"
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
              className="h-10 cursor-pointer rounded-lg border border-slate-200 bg-white px-3 text-xs font-medium text-slate-800 outline-none transition focus:border-blue-600"
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
              className="inline-flex h-10 cursor-pointer items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-40 whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-3">
          <div className="inline-flex flex-wrap gap-1 rounded-lg bg-slate-100 p-1">
            {DECISION_TABS.map((tab) => {
              const active = decisionFilter === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => onDecisionFilterChange(tab.id)}
                  className={`cursor-pointer rounded-md px-3 py-1.5 text-xs font-medium transition-all whitespace-nowrap shrink-0 ${
                    active
                      ? 'bg-white text-blue-700 font-semibold shadow-sm'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>

          <div className="font-mono text-xs font-medium text-slate-500 tabular-nums">
            Showing {events.length} {events.length === 1 ? 'event' : 'events'}
          </div>
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-200/90 bg-white shadow-[0_1px_3px_rgba(15,23,42,0.04)]">
        {loading && events.length === 0 ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="h-11 animate-pulse rounded-lg bg-slate-100" />
            ))}
          </div>
        ) : events.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <p className="text-sm font-semibold text-slate-800">No events match your current filters</p>
            <p className="mt-1 text-xs text-slate-500">
              Try clearing the search query or switching verdict and device filters.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[840px] border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-[#F8FAFC] text-[11px] font-semibold text-slate-500">
                  <th className="py-3 pl-4 pr-2.5">Time</th>
                  <th className="px-2.5 py-3">Device</th>
                  <th className="px-2.5 py-3">Verdict</th>
                  <th className="px-2.5 py-3 text-right">Score</th>
                  <th className="px-2.5 py-3">Host / Domain</th>
                  <th className="px-2.5 py-3">Primary Reason</th>
                  <th className="px-2.5 py-3">Status</th>
                  <th className="py-3 pl-2.5 pr-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
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
                      className="cursor-pointer transition-colors hover:bg-blue-50/40"
                    >
                      <td className="py-3 pl-4 pr-2.5 font-mono text-[11px] text-slate-600 tabular-nums whitespace-nowrap">
                        {formatEventTime(ev.eventTime)}
                      </td>
                      <td className="px-2.5 py-3">
                        <div className="max-w-[130px] truncate font-semibold text-slate-900 whitespace-nowrap">
                          {ev.deviceName || 'Unlabeled Device'}
                        </div>
                        <div className="max-w-[130px] truncate font-mono text-[11px] text-slate-500">
                          {ev.deviceId}
                        </div>
                      </td>
                      <td className="px-2.5 py-3 whitespace-nowrap">
                        <span className={`font-semibold ${dec.textClass}`}>
                          {dec.label}
                        </span>
                      </td>
                      <td className="px-2.5 py-3 text-right font-mono font-bold text-slate-900 tabular-nums whitespace-nowrap">
                        {ev.score}
                      </td>
                      <td className="px-2.5 py-3">
                        <div className="max-w-[150px] truncate font-mono text-slate-800">
                          {destLabel}
                        </div>
                      </td>
                      <td className="px-2.5 py-3">
                        <div className="max-w-[170px] truncate font-mono text-[11px] text-slate-600">
                          {topReason}
                        </div>
                      </td>
                      <td className="px-2.5 py-3 whitespace-nowrap">
                        <span className={`font-semibold ${st.textClass}`}>
                          {st.label}
                        </span>
                      </td>
                      <td
                        className="py-3 pl-2.5 pr-4 text-right whitespace-nowrap"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => onQuickAction(ev, 'ALLOW')}
                            title="Approve and allow opening"
                            aria-label={`Allow ${ev.requestId}`}
                            className="inline-flex h-7 cursor-pointer items-center gap-1 rounded-md border border-emerald-200 bg-emerald-50 px-2 text-[11px] font-semibold text-emerald-700 transition hover:bg-emerald-100 disabled:opacity-50"
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
                            className="inline-flex h-7 cursor-pointer items-center gap-1 rounded-md border border-rose-200 bg-rose-50 px-2 text-[11px] font-semibold text-rose-700 transition hover:bg-rose-100 disabled:opacity-50"
                          >
                            <ShieldBan className="h-3 w-3" aria-hidden="true" />
                            <span>Block</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => onOpenDetail(ev)}
                            aria-label={`Inspect ${ev.requestId}`}
                            className="inline-flex h-7 cursor-pointer items-center gap-1 rounded-md border border-slate-200 bg-white px-2 text-[11px] font-semibold text-slate-700 transition hover:bg-slate-50 hover:text-slate-900"
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
