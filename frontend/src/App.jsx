import { useCallback, useEffect, useMemo, useState } from 'react';
import { Menu, RefreshCw } from 'lucide-react';
import {
  fetchBootstrapStatus,
  verifyExistingSession,
  loginOperator,
  logoutOperator,
  listEvents,
  patchEvent,
  deleteEvent
} from './api/client.js';
import { computeDashboardInsights, filterEvents } from './utils/insights.js';
import { LoginView } from './components/LoginView.jsx';
import { SidebarNav } from './components/SidebarNav.jsx';
import { InsightsView } from './components/InsightsView.jsx';
import { EventsTableView } from './components/EventsTableView.jsx';
import { DevicesView } from './components/DevicesView.jsx';
import { EventDetailDrawer } from './components/EventDetailDrawer.jsx';

const TAB_TITLES = {
  insights: 'Overview & Insights',
  events: 'Security Events',
  devices: 'Connected Devices'
};

export default function App() {
  const [initializing, setInitializing] = useState(true);
  const [bootstrapState, setBootstrapState] = useState(null);
  const [session, setSession] = useState(null);

  const [activeTab, setActiveTab] = useState('insights');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [events, setEvents] = useState([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState('');
  const [lastSyncedAt, setLastSyncedAt] = useState(null);

  const [search, setSearch] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [deviceFilter, setDeviceFilter] = useState('ALL');

  const [selectedEventId, setSelectedEventId] = useState(null);
  const [busyRequestId, setBusyRequestId] = useState(null);

  const loadAllEvents = useCallback(async () => {
    setEventsLoading(true);
    setEventsError('');
    try {
      const collected = [];
      let offset = 0;
      const limit = 100;
      for (let page = 0; page < 5; page += 1) {
        const res = await listEvents({ limit, offset });
        const batch = Array.isArray(res?.events) ? res.events : [];
        collected.push(...batch);
        if (batch.length < limit) break;
        offset += limit;
      }
      setEvents(collected);
      setLastSyncedAt(new Date().toISOString());
    } catch (err) {
      if (err?.status === 401) {
        setSession(null);
        setEvents([]);
        setSelectedEventId(null);
      } else {
        setEventsError(err?.message || 'Could not load security events.');
      }
    } finally {
      setEventsLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    (async () => {
      const [boot, existing] = await Promise.all([
        fetchBootstrapStatus().catch(() => ({ ready: false, layer1VaultReady: false })),
        verifyExistingSession().catch(() => null)
      ]);
      if (!active) return;
      setBootstrapState(boot);
      if (existing?.authenticated) {
        setSession(existing);
      }
      setInitializing(false);
    })();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (session?.authenticated) {
      loadAllEvents();
    }
  }, [session?.authenticated, loadAllEvents]);

  const handleLogin = async ({ username, password }) => {
    const res = await loginOperator({ username, password });
    setSession({
      authenticated: true,
      username: res.username || 'pavanreddy',
      expiresAt: res.expiresAt
    });
    const boot = await fetchBootstrapStatus().catch(() => null);
    if (boot) setBootstrapState(boot);
  };

  const handleLogout = async () => {
    await logoutOperator();
    setSession(null);
    setEvents([]);
    setSelectedEventId(null);
    setActiveTab('insights');
  };

  const handlePatchEvent = async (requestId, updates) => {
    setBusyRequestId(requestId);
    try {
      const res = await patchEvent(requestId, updates);
      const updated = res?.event;
      if (updated) {
        setEvents((prev) => prev.map((ev) => (ev.requestId === requestId ? updated : ev)));
      }
      return updated;
    } catch (err) {
      if (err?.status === 401) {
        setSession(null);
      }
      throw err;
    } finally {
      setBusyRequestId(null);
    }
  };

  const handleQuickAction = async (ev, actionType) => {
    const updates =
      actionType === 'ALLOW'
        ? { decision: 'SAFE', status: 'RESOLVED', recommendedAction: 'ALLOW' }
        : { decision: 'BLOCK', status: 'OPEN', recommendedAction: 'DO_NOT_OPEN' };
    try {
      await handlePatchEvent(ev.requestId, updates);
    } catch (err) {
      setEventsError(err?.message || 'Quick action update failed.');
    }
  };

  const handleDeleteEvent = async (requestId, { archive = false } = {}) => {
    setBusyRequestId(requestId);
    try {
      const res = await deleteEvent(requestId, { archive });
      if (archive) {
        const archivedEvent = res?.event;
        if (archivedEvent) {
          setEvents((prev) => prev.map((ev) => (ev.requestId === requestId ? archivedEvent : ev)));
        } else {
          setEvents((prev) =>
            prev.map((ev) => (ev.requestId === requestId ? { ...ev, status: 'ARCHIVED' } : ev))
          );
        }
      } else {
        setEvents((prev) => prev.filter((ev) => ev.requestId !== requestId));
        setSelectedEventId((cur) => (cur === requestId ? null : cur));
      }
    } catch (err) {
      if (err?.status === 401) {
        setSession(null);
      }
      throw err;
    } finally {
      setBusyRequestId(null);
    }
  };

  const insights = useMemo(() => computeDashboardInsights(events), [events]);

  const filteredEvents = useMemo(
    () =>
      filterEvents(events, {
        search,
        decision: decisionFilter,
        status: statusFilter,
        deviceId: deviceFilter
      }),
    [events, search, decisionFilter, statusFilter, deviceFilter]
  );

  const selectedEvent = useMemo(
    () => events.find((ev) => ev.requestId === selectedEventId) || null,
    [events, selectedEventId]
  );

  const handleDrillDownDecision = (decision) => {
    setDecisionFilter(decision || 'ALL');
    setStatusFilter('ALL');
    setActiveTab('events');
  };

  const handleDrillDownDevice = (deviceId) => {
    setDeviceFilter(deviceId || 'ALL');
    setDecisionFilter('ALL');
    setStatusFilter('ALL');
    setActiveTab('events');
  };

  if (initializing) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#090D16] text-slate-400">
        <div className="flex items-center gap-3 text-sm">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-sky-400" />
          <span>Verifying SafeGate session...</span>
        </div>
      </main>
    );
  }

  if (!session?.authenticated) {
    return <LoginView bootstrapState={bootstrapState} onLogin={handleLogin} />;
  }

  const lastSyncLabel = lastSyncedAt
    ? new Date(lastSyncedAt).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : 'Syncing';

  return (
    <div className="flex min-h-screen bg-[#090D16] text-slate-100">
      <SidebarNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        devices={insights.devices}
        selectedDeviceId={deviceFilter}
        onSelectDevice={setDeviceFilter}
        openQueueCount={insights.openQueue}
        username={session.username || 'pavanreddy'}
        onLogout={handleLogout}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between gap-4 border-b border-white/[0.08] bg-[#090D16]/90 px-4 backdrop-blur sm:px-6 lg:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation menu"
              className="flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.04] text-slate-300 hover:bg-white/[0.08] lg:hidden"
            >
              <Menu className="h-4 w-4" aria-hidden="true" />
            </button>
            <div className="min-w-0">
              <h1 className="truncate text-base font-semibold tracking-tight text-slate-50 sm:text-lg">
                {TAB_TITLES[activeTab] || 'SafeGate Control'}
              </h1>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-3">
            <span className="hidden font-mono text-xs text-slate-500 tabular-nums sm:inline">
              Synced {lastSyncLabel}
            </span>
            <button
              type="button"
              onClick={loadAllEvents}
              disabled={eventsLoading}
              aria-label="Refresh security events"
              className="inline-flex h-9 cursor-pointer items-center gap-1.5 rounded-lg border border-white/[0.1] bg-white/[0.04] px-3 text-xs font-medium text-slate-200 transition hover:bg-white/[0.08] disabled:opacity-60 whitespace-nowrap"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${eventsLoading ? 'animate-spin' : ''}`}
                aria-hidden="true"
              />
              <span>Refresh</span>
            </button>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-6 sm:px-6 lg:px-8">
          {eventsError && (
            <div
              role="alert"
              className="mb-5 flex items-center justify-between gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-xs font-medium text-rose-200"
            >
              <span>{eventsError}</span>
              <button
                type="button"
                onClick={() => setEventsError('')}
                className="cursor-pointer text-rose-300 hover:text-white"
              >
                Dismiss
              </button>
            </div>
          )}

          {activeTab === 'insights' && (
            <InsightsView
              insights={insights}
              loading={eventsLoading}
              onDrillDownDecision={handleDrillDownDecision}
              onDrillDownDevice={handleDrillDownDevice}
              onRefresh={loadAllEvents}
            />
          )}

          {activeTab === 'events' && (
            <EventsTableView
              events={filteredEvents}
              devices={insights.devices}
              loading={eventsLoading}
              search={search}
              onSearchChange={setSearch}
              decisionFilter={decisionFilter}
              onDecisionFilterChange={setDecisionFilter}
              statusFilter={statusFilter}
              onStatusFilterChange={setStatusFilter}
              deviceFilter={deviceFilter}
              onDeviceFilterChange={setDeviceFilter}
              onOpenDetail={(ev) => setSelectedEventId(ev.requestId)}
              onQuickAction={handleQuickAction}
              busyRequestId={busyRequestId}
            />
          )}

          {activeTab === 'devices' && (
            <DevicesView
              devices={insights.devices}
              onInspectDeviceEvents={handleDrillDownDevice}
            />
          )}
        </main>
      </div>

      <EventDetailDrawer
        event={selectedEvent}
        onClose={() => setSelectedEventId(null)}
        onPatchEvent={handlePatchEvent}
        onDeleteEvent={handleDeleteEvent}
      />
    </div>
  );
}
