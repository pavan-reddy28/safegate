import { Smartphone, ArrowRight } from 'lucide-react';
import { formatEventTime } from '../utils/insights.js';

export function DevicesView({ devices, onInspectDeviceEvents }) {
  if (!devices || devices.length === 0) {
    return (
      <div className="rounded-xl border border-white/[0.08] bg-[#101624] p-12 text-center">
        <p className="text-sm font-medium text-slate-300">No devices reported yet</p>
        <p className="mt-1 text-xs text-slate-500">
          Hardware names such as Vivo V2355 appear automatically once a device syncs a verification check.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-[#101624]">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-white/[0.08] bg-[#0C111C] text-[11px] font-semibold text-slate-400">
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
          <tbody className="divide-y divide-white/[0.06]">
            {devices.map((dev) => (
              <tr key={dev.deviceId} className="transition-colors hover:bg-white/[0.03]">
                <td className="px-5 py-3.5">
                  <div className="flex items-center gap-2.5">
                    <Smartphone className="h-4 w-4 shrink-0 text-sky-400" aria-hidden="true" />
                    <span className="text-sm font-semibold text-slate-100">{dev.deviceName}</span>
                  </div>
                </td>
                <td className="px-5 py-3.5 font-mono text-slate-400">
                  {dev.deviceId}
                </td>
                <td className="px-5 py-3.5 text-right font-mono font-semibold text-slate-100 tabular-nums">
                  {dev.total}
                </td>
                <td className="px-5 py-3.5 text-right font-mono font-semibold text-rose-400 tabular-nums">
                  {dev.blocked}
                </td>
                <td className="px-5 py-3.5 text-right font-mono text-amber-300 tabular-nums">
                  {dev.hold + dev.suspicious}
                </td>
                <td className="px-5 py-3.5 text-right font-mono text-emerald-400 tabular-nums">
                  {dev.safe}
                </td>
                <td className="px-5 py-3.5 font-mono text-slate-400 tabular-nums whitespace-nowrap">
                  {formatEventTime(dev.lastSeenAt)}
                </td>
                <td className="px-5 py-3.5 text-right whitespace-nowrap">
                  <button
                    type="button"
                    onClick={() => onInspectDeviceEvents(dev.deviceId)}
                    className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-lg border border-white/[0.1] bg-white/[0.04] px-3 text-xs font-medium text-slate-200 transition hover:bg-white/[0.08]"
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
