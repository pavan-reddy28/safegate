export function normalizeDecision(decision) {
  const upper = String(decision || 'HOLD').toUpperCase();
  if (upper === 'BLOCKED') return 'BLOCK';
  return upper;
}

export function getDecisionStyle(decision) {
  const d = normalizeDecision(decision);
  switch (d) {
    case 'BLOCK':
      return {
        label: 'Blocked',
        textClass: 'text-rose-400',
        dotClass: 'bg-rose-500',
        barClass: 'bg-rose-500'
      };
    case 'SUSPICIOUS':
      return {
        label: 'Suspicious',
        textClass: 'text-amber-400',
        dotClass: 'bg-amber-400',
        barClass: 'bg-amber-400'
      };
    case 'HOLD':
      return {
        label: 'Hold',
        textClass: 'text-sky-400',
        dotClass: 'bg-sky-400',
        barClass: 'bg-sky-400'
      };
    case 'SAFE':
    case 'KNOWN_SAFE':
    case 'NO_KNOWN_THREAT':
      return {
        label: d === 'KNOWN_SAFE' ? 'Known Safe' : d === 'NO_KNOWN_THREAT' ? 'Cleared' : 'Safe',
        textClass: 'text-emerald-400',
        dotClass: 'bg-emerald-400',
        barClass: 'bg-emerald-400'
      };
    default:
      return {
        label: d,
        textClass: 'text-slate-300',
        dotClass: 'bg-slate-400',
        barClass: 'bg-slate-400'
      };
  }
}

export function getStatusLabel(status) {
  const s = String(status || 'OPEN').toUpperCase();
  switch (s) {
    case 'RESOLVED':
      return { label: 'Resolved', textClass: 'text-emerald-400' };
    case 'REVIEWED':
      return { label: 'Reviewed', textClass: 'text-sky-400' };
    case 'ARCHIVED':
      return { label: 'Archived', textClass: 'text-slate-400' };
    default:
      return { label: 'Open', textClass: 'text-amber-300' };
  }
}

export function formatEventTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}

export function formatFullTimestamp(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

export function computeDashboardInsights(events = []) {
  const list = Array.isArray(events) ? events : [];
  const total = list.length;

  let blocked = 0;
  let suspicious = 0;
  let hold = 0;
  let safe = 0;
  let openQueue = 0;
  let resolvedCount = 0;
  let zeroEgressCount = 0;
  let scoreSum = 0;

  const deviceMap = new Map();
  const reasonMap = new Map();
  const indicatorMap = new Map();
  const domainMap = new Map();
  const dailyMap = new Map();

  for (const ev of list) {
    const d = normalizeDecision(ev.decision);
    if (d === 'BLOCK') blocked += 1;
    else if (d === 'SUSPICIOUS') suspicious += 1;
    else if (d === 'HOLD') hold += 1;
    else safe += 1;

    const status = String(ev.status || 'OPEN').toUpperCase();
    if (status === 'OPEN') openQueue += 1;
    if (status === 'RESOLVED') resolvedCount += 1;
    if (ev.zeroEgress !== false) zeroEgressCount += 1;

    const score = Number.isFinite(Number(ev.score)) ? Number(ev.score) : 0;
    scoreSum += score;

    const devKey = ev.deviceId || 'unknown-device';
    const existingDev = deviceMap.get(devKey) || {
      deviceId: devKey,
      deviceName: ev.deviceName || 'Unlabeled Device',
      total: 0,
      blocked: 0,
      suspicious: 0,
      hold: 0,
      safe: 0,
      openCount: 0,
      lastSeenAt: ev.eventTime || ev.createdAt || null
    };
    if (ev.deviceName && (!existingDev.deviceName || existingDev.deviceName === 'Unlabeled Device')) {
      existingDev.deviceName = ev.deviceName;
    }
    existingDev.total += 1;
    if (d === 'BLOCK') existingDev.blocked += 1;
    else if (d === 'SUSPICIOUS') existingDev.suspicious += 1;
    else if (d === 'HOLD') existingDev.hold += 1;
    else existingDev.safe += 1;
    if (status === 'OPEN') existingDev.openCount += 1;
    if (ev.eventTime && (!existingDev.lastSeenAt || ev.eventTime > existingDev.lastSeenAt)) {
      existingDev.lastSeenAt = ev.eventTime;
    }
    deviceMap.set(devKey, existingDev);

    for (const reason of Array.isArray(ev.reasons) ? ev.reasons : []) {
      reasonMap.set(reason, (reasonMap.get(reason) || 0) + 1);
    }

    for (const ind of Array.isArray(ev.indicators) ? ev.indicators : []) {
      indicatorMap.set(ind, (indicatorMap.get(ind) || 0) + 1);
    }

    const host = ev.registrableDomain || ev.destinationHost || null;
    if (host) {
      domainMap.set(host, (domainMap.get(host) || 0) + 1);
    }

    if (ev.eventTime) {
      const dayKey = String(ev.eventTime).slice(0, 10);
      if (/^\d{4}-\d{2}-\d{2}$/.test(dayKey)) {
        const dayEntry = dailyMap.get(dayKey) || { day: dayKey, total: 0, blocked: 0 };
        dayEntry.total += 1;
        if (d === 'BLOCK') dayEntry.blocked += 1;
        dailyMap.set(dayKey, dayEntry);
      }
    }
  }

  const devices = [...deviceMap.values()].sort((a, b) => b.total - a.total);
  const topReasons = [...reasonMap.entries()]
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
  const topIndicators = [...indicatorMap.entries()]
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
  const topDomains = [...domainMap.entries()]
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
  const dailyActivity = [...dailyMap.values()]
    .sort((a, b) => a.day.localeCompare(b.day))
    .slice(-10);

  return {
    total,
    blocked,
    suspicious,
    hold,
    safe,
    openQueue,
    resolvedCount,
    zeroEgressRate: total > 0 ? Math.round((zeroEgressCount / total) * 100) : 100,
    avgScore: total > 0 ? Math.round(scoreSum / total) : 0,
    uniqueDevices: devices.length,
    devices,
    topReasons,
    topIndicators,
    topDomains,
    dailyActivity
  };
}

export function filterEvents(events = [], { search = '', decision = 'ALL', status = 'ALL', deviceId = 'ALL' } = {}) {
  const q = String(search || '').trim().toLowerCase();
  return (Array.isArray(events) ? events : []).filter((ev) => {
    if (decision !== 'ALL') {
      const norm = normalizeDecision(ev.decision);
      if (decision === 'SAFE') {
        if (norm !== 'SAFE' && norm !== 'KNOWN_SAFE' && norm !== 'NO_KNOWN_THREAT') return false;
      } else if (norm !== decision) {
        return false;
      }
    }

    if (status !== 'ALL' && String(ev.status || '').toUpperCase() !== status) {
      return false;
    }

    if (deviceId !== 'ALL' && ev.deviceId !== deviceId) {
      return false;
    }

    if (!q) return true;

    const haystack = [
      ev.requestId,
      ev.deviceId,
      ev.deviceName,
      ev.destinationHost,
      ev.registrableDomain,
      ev.notes,
      ev.decision,
      ev.localDecision,
      ev.recommendedAction,
      ...(Array.isArray(ev.reasons) ? ev.reasons : []),
      ...(Array.isArray(ev.indicators) ? ev.indicators : [])
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();

    return haystack.includes(q);
  });
}

function csvSafeCell(value) {
  const text = String(value ?? '');
  const guarded = /^[=+\-@]/.test(text) ? `'${text}` : text;
  return `"${guarded.replaceAll('"', '""')}"`;
}

export function exportEventsToCsv(events = []) {
  const headers = [
    'requestId',
    'eventTime',
    'deviceName',
    'deviceId',
    'decision',
    'score',
    'status',
    'recommendedAction',
    'destinationHost',
    'registrableDomain',
    'reasons',
    'indicators',
    'notes'
  ];

  const rows = events.map((ev) =>
    [
      ev.requestId,
      ev.eventTime,
      ev.deviceName || '',
      ev.deviceId,
      ev.decision,
      ev.score,
      ev.status,
      ev.recommendedAction || '',
      ev.destinationHost || '',
      ev.registrableDomain || '',
      (ev.reasons || []).join(';'),
      (ev.indicators || []).join(';'),
      ev.notes || ''
    ]
      .map(csvSafeCell)
      .join(',')
  );

  return [headers.join(','), ...rows].join('\n');
}
