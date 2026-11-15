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
        barClass: 'bg-rose-500',
        hex: '#F43F5E'
      };
    case 'SUSPICIOUS':
      return {
        label: 'Suspicious',
        textClass: 'text-amber-400',
        dotClass: 'bg-amber-400',
        barClass: 'bg-amber-400',
        hex: '#FBBF24'
      };
    case 'HOLD':
      return {
        label: 'Hold',
        textClass: 'text-sky-400',
        dotClass: 'bg-sky-400',
        barClass: 'bg-sky-400',
        hex: '#38BDF8'
      };
    case 'SAFE':
    case 'KNOWN_SAFE':
    case 'NO_KNOWN_THREAT':
      return {
        label: d === 'KNOWN_SAFE' ? 'Known Safe' : d === 'NO_KNOWN_THREAT' ? 'Cleared' : 'Safe',
        textClass: 'text-emerald-400',
        dotClass: 'bg-emerald-400',
        barClass: 'bg-emerald-400',
        hex: '#34D399'
      };
    default:
      return {
        label: d,
        textClass: 'text-slate-300',
        dotClass: 'bg-slate-400',
        barClass: 'bg-slate-400',
        hex: '#94A3B8'
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

function formatCheckLabel(key) {
  return String(key || '')
    .replace(/Check$/, '')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/^./, (c) => c.toUpperCase());
}

export function filterEventsByRangeAndDevice(events = [], { range = 'ALL', deviceId = 'ALL', nowMs = Date.now() } = {}) {
  const list = Array.isArray(events) ? events : [];
  let cutoffMs = null;
  if (range === '24H') cutoffMs = nowMs - 24 * 3600 * 1000;
  else if (range === '7D') cutoffMs = nowMs - 7 * 24 * 3600 * 1000;
  else if (range === '30D') cutoffMs = nowMs - 30 * 24 * 3600 * 1000;

  return list.filter((ev) => {
    if (deviceId && deviceId !== 'ALL' && ev.deviceId !== deviceId) {
      return false;
    }
    if (cutoffMs !== null) {
      const ts = new Date(ev.eventTime || ev.createdAt || 0).getTime();
      if (!Number.isFinite(ts) || ts < cutoffMs) return false;
    }
    return true;
  });
}

export function computeDashboardInsights(events = [], options = {}) {
  const allEvents = Array.isArray(events) ? events : [];
  const list = options && (options.range || options.deviceId)
    ? filterEventsByRangeAndDevice(allEvents, options)
    : allEvents;
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
  const hourlyMap = new Map();
  const checkMap = new Map();

  const riskBuckets = [
    { id: '0-20', label: '0–20', hint: 'Low', min: 0, max: 20, count: 0, color: '#34D399' },
    { id: '21-49', label: '21–49', hint: 'Moderate', min: 21, max: 49, count: 0, color: '#38BDF8' },
    { id: '50-74', label: '50–74', hint: 'Elevated', min: 50, max: 74, count: 0, color: '#FBBF24' },
    { id: '75-100', label: '75–100', hint: 'Critical', min: 75, max: 100, count: 0, color: '#F43F5E' }
  ];

  // Always compute connected device inventory across allEvents so device selector never loses devices
  for (const ev of allEvents) {
    const dAll = normalizeDecision(ev.decision);
    const statusAll = String(ev.status || 'OPEN').toUpperCase();
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
    if (dAll === 'BLOCK') existingDev.blocked += 1;
    else if (dAll === 'SUSPICIOUS') existingDev.suspicious += 1;
    else if (dAll === 'HOLD') existingDev.hold += 1;
    else existingDev.safe += 1;
    if (statusAll === 'OPEN') existingDev.openCount += 1;
    if (ev.eventTime && (!existingDev.lastSeenAt || ev.eventTime > existingDev.lastSeenAt)) {
      existingDev.lastSeenAt = ev.eventTime;
    }
    deviceMap.set(devKey, existingDev);
  }

  let latestTsMs = 0;

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

    const score = Number.isFinite(Number(ev.score)) ? Math.min(100, Math.max(0, Number(ev.score))) : 0;
    scoreSum += score;
    for (const bucket of riskBuckets) {
      if (score >= bucket.min && score <= bucket.max) {
        bucket.count += 1;
        break;
      }
    }

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

    const checks = ev.securityChecks && typeof ev.securityChecks === 'object' ? ev.securityChecks : {};
    for (const [ckKey, ckVal] of Object.entries(checks)) {
      if (ckKey === 'zeroEgressGuaranteed') continue;
      const entry = checkMap.get(ckKey) || {
        key: ckKey,
        label: formatCheckLabel(ckKey),
        passed: 0,
        flagged: 0,
        failed: 0,
        total: 0
      };
      const valUpper = String(ckVal || '').toUpperCase();
      if (valUpper === 'PASSED' || ckVal === true) entry.passed += 1;
      else if (valUpper === 'FAILED' || ckVal === false) entry.failed += 1;
      else entry.flagged += 1;
      entry.total += 1;
      checkMap.set(ckKey, entry);
    }

    const eventIso = ev.eventTime || ev.createdAt;
    if (eventIso) {
      const parsedDate = new Date(eventIso);
      const ms = parsedDate.getTime();
      if (Number.isFinite(ms) && ms > latestTsMs) latestTsMs = ms;

      const dayKey = String(eventIso).slice(0, 10);
      if (/^\d{4}-\d{2}-\d{2}$/.test(dayKey)) {
        const dayEntry = dailyMap.get(dayKey) || {
          day: dayKey,
          label: dayKey.slice(5),
          total: 0,
          blocked: 0,
          suspicious: 0,
          hold: 0,
          safe: 0,
          scoreTotal: 0
        };
        dayEntry.total += 1;
        dayEntry.scoreTotal += score;
        if (d === 'BLOCK') dayEntry.blocked += 1;
        else if (d === 'SUSPICIOUS') dayEntry.suspicious += 1;
        else if (d === 'HOLD') dayEntry.hold += 1;
        else dayEntry.safe += 1;
        dailyMap.set(dayKey, dayEntry);
      }

      if (Number.isFinite(ms)) {
        const hourKey = parsedDate.toISOString().slice(0, 13); // YYYY-MM-DDTHH
        const hourEntry = hourlyMap.get(hourKey) || {
          day: hourKey,
          label: `${hourKey.slice(11, 13)}:00`,
          total: 0,
          blocked: 0,
          suspicious: 0,
          hold: 0,
          safe: 0,
          scoreTotal: 0
        };
        hourEntry.total += 1;
        hourEntry.scoreTotal += score;
        if (d === 'BLOCK') hourEntry.blocked += 1;
        else if (d === 'SUSPICIOUS') hourEntry.suspicious += 1;
        else if (d === 'HOLD') hourEntry.hold += 1;
        else hourEntry.safe += 1;
        hourlyMap.set(hourKey, hourEntry);
      }
    }
  }

  // Build padded 7-day continuous series up to latest event date so charts show real trend geometry even on new deployments
  const dailyActivity = [];
  if (dailyMap.size > 0) {
    const anchorMs = latestTsMs || Date.now();
    const earliestDay = [...dailyMap.keys()].sort()[0];
    const spanDays = Math.min(
      14,
      Math.max(
        7,
        Math.ceil((anchorMs - new Date(`${earliestDay}T00:00:00Z`).getTime()) / (24 * 3600 * 1000)) + 1
      )
    );
    for (let i = spanDays - 1; i >= 0; i -= 1) {
      const dt = new Date(anchorMs - i * 24 * 3600 * 1000);
      const dayKey = dt.toISOString().slice(0, 10);
      const existing = dailyMap.get(dayKey);
      if (existing) {
        dailyActivity.push({
          ...existing,
          avgScore: Math.round(existing.scoreTotal / Math.max(1, existing.total))
        });
      } else {
        dailyActivity.push({
          day: dayKey,
          label: dayKey.slice(5),
          total: 0,
          blocked: 0,
          suspicious: 0,
          hold: 0,
          safe: 0,
          scoreTotal: 0,
          avgScore: 0
        });
      }
    }
  }

  // Build 12-hour trailing series when Hourly view or 24H range is inspected
  const hourlyActivity = [];
  if (hourlyMap.size > 0) {
    const anchorMs = latestTsMs || Date.now();
    for (let i = 11; i >= 0; i -= 1) {
      const dt = new Date(anchorMs - i * 3600 * 1000);
      const hourKey = dt.toISOString().slice(0, 13);
      const existing = hourlyMap.get(hourKey);
      if (existing) {
        hourlyActivity.push({
          ...existing,
          avgScore: Math.round(existing.scoreTotal / Math.max(1, existing.total))
        });
      } else {
        hourlyActivity.push({
          day: hourKey,
          label: `${hourKey.slice(11, 13)}:00`,
          total: 0,
          blocked: 0,
          suspicious: 0,
          hold: 0,
          safe: 0,
          scoreTotal: 0,
          avgScore: 0
        });
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
  const checkBreakdown = [...checkMap.values()]
    .map((item) => ({
      ...item,
      passRate: item.total > 0 ? Math.round((item.passed / item.total) * 100) : 100
    }))
    .sort((a, b) => a.passRate - b.passRate || b.total - a.total);

  const sparkSource = dailyActivity.slice(-7);
  const sparklines = {
    total: sparkSource.map((d) => d.total),
    blocked: sparkSource.map((d) => d.blocked),
    queue: sparkSource.map((d) => d.hold + d.suspicious),
    safe: sparkSource.map((d) => d.safe)
  };

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
    dailyActivity,
    hourlyActivity,
    riskBuckets,
    checkBreakdown,
    sparklines
  };
}

export function filterEvents(events = [], { search = '', decision = 'ALL', status = 'ALL', deviceId = 'ALL', riskBand = 'ALL' } = {}) {
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

    if (riskBand && riskBand !== 'ALL') {
      const sc = Number.isFinite(Number(ev.score)) ? Number(ev.score) : 0;
      if (riskBand === '0-20' && (sc < 0 || sc > 20)) return false;
      if (riskBand === '21-49' && (sc < 21 || sc > 49)) return false;
      if (riskBand === '50-74' && (sc < 50 || sc > 74)) return false;
      if (riskBand === '75-100' && (sc < 75 || sc > 100)) return false;
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
