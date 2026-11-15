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
    <div className="flex h-full w-64 flex-col border-r border-slate-200/90 bg-white">
      <div className="flex h-16 items-center justify-between border-b border-slate-200/80 px-5">
        <div className="flex items-center gap-2.5">
          <LockerMark className="h-6 w-6 shrink-0" />
          <span className="font-display whitespace-nowrap text-base font-bold tracking-tight text-slate-900">
            SafeGate
          </span>
        </div>
        {mobileOpen && (
          <button
            type="button"
            onClick={onCloseMobile}
            aria-label="Close navigation menu"
            className="flex h-9 w-9 cursor-pointer items-center justify-center rounded-lg text-slate-500 transition hover:bg-slate-100 hover:text-slate-900 lg:hidden"
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
                  ? 'bg-blue-50 text-blue-700 font-semibold'
                  : 'text-slate-600 hover:bg-slate-100/80 hover:text-slate-900'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Icon
                  className={`h-4 w-4 shrink-0 ${active ? 'text-blue-600' : 'text-slate-500'}`}
                  aria-hidden="true"
                />
                <span>{item.label}</span>
              </span>
              {typeof item.count === 'number' && (
                <span
                  className={`font-mono text-xs tabular-nums ${
                    active ? 'text-blue-600 font-semibold' : 'text-slate-500'
                  }`}
                >
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="mt-1 flex-1 overflow-y-auto border-t border-slate-100 px-3 py-4">
        <div className="px-3 text-xs font-semibold text-slate-500">
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
                      ? 'bg-blue-50 text-blue-700 font-semibold'
                      : 'text-slate-700 hover:bg-slate-100/80 hover:text-slate-900'
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

      <div className="border-t border-slate-200/80 p-4">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-slate-900">
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
            className="flex h-9 cursor-pointer items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 text-xs font-medium text-slate-700 transition hover:bg-slate-100 hover:text-slate-900 whitespace-nowrap shrink-0"
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
            className="fixed inset-0 bg-slate-900/35 backdrop-blur-[2px]"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <aside className="relative z-10 h-full shadow-xl">{content}</aside>
        </div>
      )}
    </>
  );
}
