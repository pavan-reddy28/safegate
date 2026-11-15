import { BarChart3, ShieldAlert, Smartphone, LogOut, X } from 'lucide-react';
import { LockerMark } from './LockerMark.jsx';

export function SidebarNav({
  activeTab,
  onSelectTab,
  devices,
  selectedDeviceId,
  onSelectDevice,
  openQueueCount,
  username,
  onLogout,
  mobileOpen,
  onCloseMobile
}) {
  const navItems = [
    { id: 'insights', label: 'Insights', icon: BarChart3 },
    { id: 'events', label: 'Security Events', icon: ShieldAlert, count: openQueueCount },
    { id: 'devices', label: 'Devices', icon: Smartphone, count: devices.length }
  ];

  const handleNavClick = (id) => {
    onSelectTab(id);
    onCloseMobile?.();
  };

  const handleDeviceClick = (deviceId) => {
    onSelectDevice(deviceId === selectedDeviceId ? 'ALL' : deviceId);
    onSelectTab('events');
    onCloseMobile?.();
  };

  const content = (
    <div className="flex h-full w-64 flex-col border-r border-white/[0.08] bg-[#0C111C]">
      <div className="flex h-16 items-center justify-between border-b border-white/[0.08] px-5">
        <div className="flex items-center gap-2.5">
          <LockerMark className="h-6 w-6 shrink-0" />
          <span className="whitespace-nowrap text-base font-semibold tracking-tight text-slate-50">
            SafeGate
          </span>
        </div>
        {mobileOpen && (
          <button
            type="button"
            onClick={onCloseMobile}
            aria-label="Close navigation menu"
            className="flex h-9 w-9 cursor-pointer items-center justify-center rounded-lg text-slate-400 hover:bg-white/[0.06] hover:text-slate-100 lg:hidden"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        )}
      </div>

      <nav aria-label="Primary dashboard sections" className="space-y-1 px-3 py-4">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => handleNavClick(item.id)}
              className={`flex h-10 w-full cursor-pointer items-center justify-between rounded-lg px-3 text-sm font-medium transition-colors whitespace-nowrap ${
                active
                  ? 'bg-white/[0.08] text-slate-50'
                  : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                <span>{item.label}</span>
              </span>
              {typeof item.count === 'number' && (
                <span className="font-mono text-xs text-slate-400 tabular-nums">
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="mt-2 flex-1 overflow-y-auto border-t border-white/[0.07] px-3 py-4">
        <div className="px-3 text-xs font-medium text-slate-500">
          Connected Devices
        </div>
        {devices.length === 0 ? (
          <p className="mt-2.5 px-3 text-xs text-slate-500">
            No devices synced yet.
          </p>
        ) : (
          <div className="mt-2 space-y-1">
            {devices.map((dev) => {
              const active = selectedDeviceId === dev.deviceId && activeTab === 'events';
              return (
                <button
                  key={dev.deviceId}
                  type="button"
                  onClick={() => handleDeviceClick(dev.deviceId)}
                  className={`flex w-full cursor-pointer items-center justify-between rounded-lg px-3 py-2 text-left text-xs transition-colors ${
                    active
                      ? 'bg-sky-500/15 text-sky-200'
                      : 'text-slate-300 hover:bg-white/[0.04] hover:text-white'
                  }`}
                >
                  <span className="min-w-0 truncate font-medium">
                    {dev.deviceName}
                  </span>
                  <span className="ml-2 shrink-0 font-mono text-[11px] text-slate-500 tabular-nums">
                    {dev.total}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      <div className="border-t border-white/[0.08] p-4">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-slate-100">
              {username}
            </div>
            <div className="text-xs text-slate-500">
              Single-owner access
            </div>
          </div>
          <button
            type="button"
            onClick={onLogout}
            aria-label="Sign out"
            className="flex h-9 cursor-pointer items-center gap-1.5 rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 text-xs font-medium text-slate-300 transition hover:bg-white/[0.08] hover:text-white whitespace-nowrap shrink-0"
          >
            <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Sign out</span>
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <>
      <aside className="hidden lg:sticky lg:top-0 lg:block lg:h-screen lg:shrink-0">{content}</aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <aside className="relative z-10 h-full">{content}</aside>
        </div>
      )}
    </>
  );
}
