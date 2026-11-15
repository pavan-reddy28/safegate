import { Smartphone, ArrowRight } from 'lucide-react';
import { formatEventTime } from '../utils/insights.js';

export function DevicesView({ devices, onInspectDeviceEvents }) {
  if (!devices || devices.length === 0) {
    return (
      <div className="sg-animate-enter rounded-xl border border-slate-200/90 bg-white p-12 text-center shadow-[0_1px_3px_rgba(15,23,42,0.04)]">
        <p className="text-sm font-semibold text-slate-800">No devices reported yet</p>
        <p className="mt-1 text-xs text-slate-500">
          Hardware names such as Vivo V2355 appear automatically once a device syncs a verification check.
        </p>
      </div>
    );
  }

  return (
    <div className="sg-animate-enter overflow-hidden rounded-xl border border-slate-200/90 bg-white shadow-[0_1px_3px_rgba(15,23,42,0.04)]">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-slate-200 bg-[#F8FAFC] text-[11px] font-semibold text-slate-500">
              <th className="px-5 py-3">Hardware Device Name</th>
              <th className="px-5 py-3">Device ID</th>
              <th className="px-5 py-3 text-right">Total Scans</th>
              <th className="px-5 py-3 text-right">Blocked</th>
              <th className="px-5 py-3 text-right">Hold / Suspicious</th>
              <th className="px-5 py-3 text-right">Safe</th>
              <th className="px-5 py-3">Last Seen</th>
              <th className="px-5 py-3 text-right">Events</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {devices.map((dev) => (
              <tr key={dev.deviceId} className="transition-colors hover:bg-blue-50/40">
                <td className="px-5 py-3.5">
                  <div className="flex items-center gap-2.5">
                    <Smartphone className="h-4 w-4 shrink-0 text-blue-600" aria-hidden="true" />
                    <span className="text-sm font-semibold text-slate-900">{dev.deviceName}</span>
                  </div>
                </td>
                <td className="px-5 py-3.5 font-mono text-slate-500">
                  {dev.deviceId}
                </td>
                <td className="px-5 py-3.5 text-right font-mono font-bold text-slate-900 tabular-nums">
                  {dev.total}
                </td>
                <td className="px-5 py-3.5 text-right font-mono font-semibold text-rose-600 tabular-nums">
                  {dev.blocked}
                </td>
                <td className="px-5 py-3.5 text-right font-mono font-semibold text-amber-600 tabular-nums">
                  {dev.hold + dev.suspicious}
                </td>
                <td className="px-5 py-3.5 text-right font-mono font-semibold text-emerald-600 tabular-nums">
                  {dev.safe}
                </td>
                <td className="px-5 py-3.5 font-mono text-slate-600 tabular-nums whitespace-nowrap">
                  {formatEventTime(dev.lastSeenAt)}
                </td>
                <td className="px-5 py-3.5 text-right whitespace-nowrap">
                  <button
                    type="button"
                    onClick={() => onInspectDeviceEvents(dev.deviceId)}
                    className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 text-xs font-semibold text-slate-700 transition hover:border-blue-300 hover:bg-blue-50/50 hover:text-blue-700"
                  >
                    <span>View Events</span>
                    <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
