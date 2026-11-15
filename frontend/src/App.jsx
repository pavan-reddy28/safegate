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

  const [insightsRange, setInsightsRange] = useState('ALL');
  const [insightsDeviceScope, setInsightsDeviceScope] = useState('ALL');

  const [search, setSearch] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [deviceFilter, setDeviceFilter] = useState('ALL');
  const [riskBandFilter, setRiskBandFilter] = useState('ALL');

  const [selectedEventId, setSelectedEventId] = useState(null);
  const [busyRequestId, setBusyRequestId] = useState(null);

  const loadAllEvents = useCallback(async ({ silent = false } = {}) => {
    if (!silent) {
      setEventsLoading(true);
      setEventsError('');
    }
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
      } else if (!silent) {
        setEventsError(err?.message || 'Could not load security events.');
      }
    } finally {
      if (!silent) {
        setEventsLoading(false);
      }
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
    if (!session?.authenticated) return undefined;
    loadAllEvents();

    const intervalId = window.setInterval(() => {
      if (typeof document === 'undefined' || document.visibilityState === 'visible') {
        loadAllEvents({ silent: true });
      }
    }, 10000);

    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        loadAllEvents({ silent: true });
      }
    };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      window.clearInterval(intervalId);
      document.removeEventListener('visibilitychange', onVisibility);
    };
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

  const globalInsights = useMemo(() => computeDashboardInsights(events), [events]);

  const scopedInsights = useMemo(
    () =>
      computeDashboardInsights(events, {
        range: insightsRange,
        deviceId: insightsDeviceScope
      }),
    [events, insightsRange, insightsDeviceScope]
  );

  const filteredEvents = useMemo(
    () =>
      filterEvents(events, {
        search,
        decision: decisionFilter,
        status: statusFilter,
        deviceId: deviceFilter,
        riskBand: riskBandFilter
      }),
    [events, search, decisionFilter, statusFilter, deviceFilter, riskBandFilter]
  );

  const selectedEvent = useMemo(
    () => events.find((ev) => ev.requestId === selectedEventId) || null,
    [events, selectedEventId]
  );

  const handleDrillDownDecision = (decision) => {
    setDecisionFilter(decision || 'ALL');
    setStatusFilter('ALL');
    setRiskBandFilter('ALL');
    if (insightsDeviceScope !== 'ALL') {
      setDeviceFilter(insightsDeviceScope);
    }
    setActiveTab('events');
  };

  const handleDrillDownDevice = (deviceId) => {
    setDeviceFilter(deviceId || 'ALL');
    setDecisionFilter('ALL');
    setStatusFilter('ALL');
    setRiskBandFilter('ALL');
    setActiveTab('events');
  };

  const handleDrillDownRiskBand = (band) => {
    setRiskBandFilter(band || 'ALL');
    setDecisionFilter('ALL');
    setStatusFilter('ALL');
    if (insightsDeviceScope !== 'ALL') {
      setDeviceFilter(insightsDeviceScope);
    }
    setActiveTab('events');
  };

  const handleDrillDownDomain = (domain) => {
    setSearch(domain || '');
    setDecisionFilter('ALL');
    setStatusFilter('ALL');
    setRiskBandFilter('ALL');
    if (insightsDeviceScope !== 'ALL') {
      setDeviceFilter(insightsDeviceScope);
    }
    setActiveTab('events');
  };

  if (initializing) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#F8FAFC] text-slate-600">
        <div className="flex items-center gap-3 text-sm font-medium">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-blue-600" />
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
    <div className="flex min-h-screen bg-[#F8FAFC] text-slate-900">
      <SidebarNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        devices={globalInsights.devices}
        selectedDeviceId={deviceFilter}
        onSelectDevice={(id) => {
          setRiskBandFilter('ALL');
          setDeviceFilter(id);
        }}
        openQueueCount={globalInsights.openQueue}
        username={session.username || 'pavanreddy'}
        onLogout={handleLogout}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between gap-4 border-b border-slate-200/80 bg-white/90 px-4 backdrop-blur-md sm:px-6 lg:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation menu"
              className="flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-700 transition hover:bg-slate-50 lg:hidden"
            >
              <Menu className="h-4 w-4" aria-hidden="true" />
            </button>
            <div className="min-w-0">
              <h1 className="font-display truncate text-base font-bold tracking-tight text-slate-900 sm:text-lg">
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
              className="inline-flex h-9 cursor-pointer items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 text-xs font-semibold text-slate-700 shadow-[0_1px_2px_rgba(15,23,42,0.03)] transition hover:bg-slate-50 hover:text-slate-900 disabled:opacity-60 whitespace-nowrap"
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
              className="mb-5 flex items-center justify-between gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-xs font-medium text-rose-700"
            >
              <span>{eventsError}</span>
              <button
                type="button"
                onClick={() => setEventsError('')}
                className="cursor-pointer font-semibold text-rose-800 hover:text-rose-950"
              >
                Dismiss
              </button>
            </div>
          )}

          {activeTab === 'insights' && (
            <InsightsView
              insights={scopedInsights}
              totalStoredCount={events.length}
              range={insightsRange}
              onRangeChange={setInsightsRange}
              scopeDeviceId={insightsDeviceScope}
              onScopeDeviceChange={setInsightsDeviceScope}
              loading={eventsLoading}
              onDrillDownDecision={handleDrillDownDecision}
              onDrillDownDevice={handleDrillDownDevice}
              onDrillDownRiskBand={handleDrillDownRiskBand}
              onDrillDownDomain={handleDrillDownDomain}
              onRefresh={loadAllEvents}
            />
          )}

          {activeTab === 'events' && (
            <EventsTableView
              events={filteredEvents}
              devices={globalInsights.devices}
              loading={eventsLoading}
              search={search}
              onSearchChange={setSearch}
              decisionFilter={decisionFilter}
              onDecisionFilterChange={setDecisionFilter}
              statusFilter={statusFilter}
              onStatusFilterChange={setStatusFilter}
              deviceFilter={deviceFilter}
              onDeviceFilterChange={setDeviceFilter}
              riskBandFilter={riskBandFilter}
              onRiskBandFilterChange={setRiskBandFilter}
              onOpenDetail={(ev) => setSelectedEventId(ev.requestId)}
              onQuickAction={handleQuickAction}
              busyRequestId={busyRequestId}
            />
          )}

          {activeTab === 'devices' && (
            <DevicesView
              devices={globalInsights.devices}
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
