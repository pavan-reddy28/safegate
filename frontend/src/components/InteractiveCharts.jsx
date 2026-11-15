import { useEffect, useMemo, useState } from 'react';

export function AnimatedNumber({ value = 0, suffix = '', durationMs = 550 }) {
  const target = Number.isFinite(Number(value)) ? Number(value) : 0;
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches;
    if (prefersReduced) {
      setDisplay(target);
      return undefined;
    }

    let frameId = null;
    const startVal = display;
    const startTime = performance.now();

    const tick = (now) => {
      const progress = Math.min(1, (now - startTime) / durationMs);
      const eased = 1 - (1 - progress) ** 3;
      setDisplay(Math.round(startVal + (target - startVal) * eased));
      if (progress < 1) {
        frameId = requestAnimationFrame(tick);
      }
    };

    frameId = requestAnimationFrame(tick);
    return () => {
      if (frameId !== null) cancelAnimationFrame(frameId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);

  return (
    <span className="tabular-nums">
      {display}
      {suffix}
    </span>
  );
}

export function MiniSparkline({ data = [], stroke = '#38BDF8', id = 'spark' }) {
  const points = Array.isArray(data) && data.length > 1 ? data : [0, ...(Array.isArray(data) ? data : [0]), 0];
  const width = 112;
  const height = 34;
  const padY = 4;
  const max = Math.max(1, ...points);

  const coords = points.map((val, idx) => {
    const x = (idx / Math.max(1, points.length - 1)) * width;
    const y = height - padY - ((val / max) * (height - padY * 2));
    return { x, y };
  });

  const linePath = coords
    .map((p, i) => {
      if (i === 0) return `M ${p.x.toFixed(1)} ${p.y.toFixed(1)}`;
      const prev = coords[i - 1];
      const cx = ((prev.x + p.x) / 2).toFixed(1);
      return `C ${cx} ${prev.y.toFixed(1)}, ${cx} ${p.y.toFixed(1)}, ${p.x.toFixed(1)} ${p.y.toFixed(1)}`;
    })
    .join(' ');

  const areaPath = `${linePath} L ${width} ${height} L 0 ${height} Z`;
  const gradId = `sg-spark-${id}`;

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="h-9 w-24 shrink-0 overflow-visible"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={stroke} stopOpacity="0.28" />
          <stop offset="100%" stopColor={stroke} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#${gradId})`} />
      <path
        d={linePath}
        fill="none"
        stroke={stroke}
        strokeWidth="1.75"
        strokeLinecap="round"
        className="sg-path-draw"
      />
    </svg>
  );
}

function buildSmoothSpline(coords) {
  if (!coords.length) return '';
  return coords
    .map((p, i) => {
      if (i === 0) return `M ${p.x.toFixed(1)} ${p.y.toFixed(1)}`;
      const prev = coords[i - 1];
      const cx = ((prev.x + p.x) / 2).toFixed(1);
      return `C ${cx} ${prev.y.toFixed(1)}, ${cx} ${p.y.toFixed(1)}, ${p.x.toFixed(1)} ${p.y.toFixed(1)}`;
    })
    .join(' ');
}

export function TimelineAreaChart({
  dailySeries = [],
  hourlySeries = [],
  onSelectDecision
}) {
  const [chartMode, setChartMode] = useState('area'); // 'area' | 'bars'
  const [granularity, setGranularity] = useState('daily'); // 'daily' | 'hourly'
  const [hoveredIdx, setHoveredIdx] = useState(null);

  const series = granularity === 'hourly' ? hourlySeries : dailySeries;

  const chart = useMemo(() => {
    const width = 680;
    const height = 230;
    const padLeft = 36;
    const padRight = 18;
    const padTop = 18;
    const padBottom = 30;
    const innerW = width - padLeft - padRight;
    const innerH = height - padTop - padBottom;
    const maxVal = Math.max(2, ...series.map((d) => d.total || 0));

    const pts = series.map((d, i) => {
      const ratioX = series.length > 1 ? i / (series.length - 1) : 0.5;
      const x = padLeft + ratioX * innerW;
      const totalY = padTop + innerH - ((d.total || 0) / maxVal) * innerH;
      const blockedY = padTop + innerH - ((d.blocked || 0) / maxVal) * innerH;
      const safeY = padTop + innerH - ((d.safe || 0) / maxVal) * innerH;
      return { ...d, idx: i, x, totalY, blockedY, safeY };
    });

    const totalLine = buildSmoothSpline(pts.map((p) => ({ x: p.x, y: p.totalY })));
    const blockedLine = buildSmoothSpline(pts.map((p) => ({ x: p.x, y: p.blockedY })));
    const bottomY = padTop + innerH;
    const totalArea = pts.length
      ? `${totalLine} L ${pts[pts.length - 1].x.toFixed(1)} ${bottomY} L ${pts[0].x.toFixed(1)} ${bottomY} Z`
      : '';
    const blockedArea = pts.length
      ? `${blockedLine} L ${pts[pts.length - 1].x.toFixed(1)} ${bottomY} L ${pts[0].x.toFixed(1)} ${bottomY} Z`
      : '';

    const ticks = [0, Math.ceil(maxVal / 2), maxVal];
    return { width, height, padLeft, padRight, padTop, padBottom, innerW, innerH, bottomY, maxVal, pts, totalLine, blockedLine, totalArea, blockedArea, ticks };
  }, [series]);

  const activePoint = hoveredIdx !== null && chart.pts[hoveredIdx]
    ? chart.pts[hoveredIdx]
    : chart.pts[chart.pts.length - 1] || null;

  return (
    <section className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-[#101624] p-6 transition-colors hover:border-white/[0.14]">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Threat &amp; Inspection Timeline</h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Hover across time buckets to inspect scans, blocked threats, and cleared links
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex rounded-lg border border-white/[0.08] bg-[#0B101B] p-0.5 text-[11px]">
            <button
              type="button"
              onClick={() => {
                setGranularity('daily');
                setHoveredIdx(null);
              }}
              className={`cursor-pointer rounded-md px-2.5 py-1 font-medium transition ${
                granularity === 'daily' ? 'bg-white/[0.1] text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Daily
            </button>
            <button
              type="button"
              onClick={() => {
                setGranularity('hourly');
                setHoveredIdx(null);
              }}
              className={`cursor-pointer rounded-md px-2.5 py-1 font-medium transition ${
                granularity === 'hourly' ? 'bg-white/[0.1] text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              12h Hourly
            </button>
          </div>

          <div className="inline-flex rounded-lg border border-white/[0.08] bg-[#0B101B] p-0.5 text-[11px]">
            <button
              type="button"
              onClick={() => setChartMode('area')}
              className={`cursor-pointer rounded-md px-2.5 py-1 font-medium transition ${
                chartMode === 'area' ? 'bg-sky-500/20 text-sky-300' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Spline Area
            </button>
            <button
              type="button"
              onClick={() => setChartMode('bars')}
              className={`cursor-pointer rounded-md px-2.5 py-1 font-medium transition ${
                chartMode === 'bars' ? 'bg-sky-500/20 text-sky-300' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Stacked Bars
            </button>
          </div>
        </div>
      </div>

      {/* Live readout strip */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-white/[0.06] bg-[#0B101B] px-3.5 py-2 text-xs">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono tabular-nums">
          <span className="whitespace-nowrap text-slate-400">
            Window: <strong className="text-slate-100">{activePoint ? activePoint.day : '—'}</strong>
          </span>
          <span className="whitespace-nowrap text-sky-400">
            Total <strong>{activePoint?.total ?? 0}</strong>
          </span>
          <span className="whitespace-nowrap text-rose-400">
            Blocked <strong>{activePoint?.blocked ?? 0}</strong>
          </span>
          <span className="whitespace-nowrap text-emerald-400">
            Safe <strong>{activePoint?.safe ?? 0}</strong>
          </span>
        </div>
        <div className="flex items-center gap-3 text-[11px] text-slate-400">
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-sm bg-sky-400" />
            Total Scans
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-sm bg-rose-500" />
            Blocked
          </span>
        </div>
      </div>

      {series.length === 0 ? (
        <div className="flex h-56 items-center justify-center text-xs text-slate-500">
          No dated events in this range yet.
        </div>
      ) : (
        <div className="relative mt-4">
          <svg
            viewBox={`0 0 ${chart.width} ${chart.height}`}
            className="h-56 w-full select-none overflow-visible"
            role="img"
            aria-label="Threat and inspection activity timeline chart"
            onMouseLeave={() => setHoveredIdx(null)}
          >
            <defs>
              <linearGradient id="sg-total-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.32" />
                <stop offset="100%" stopColor="#38BDF8" stopOpacity="0.01" />
              </linearGradient>
              <linearGradient id="sg-blocked-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#F43F5E" stopOpacity="0.38" />
                <stop offset="100%" stopColor="#F43F5E" stopOpacity="0.02" />
              </linearGradient>
            </defs>

            {/* Horizontal grid lines */}
            {chart.ticks.map((tickVal) => {
              const y = chart.padTop + chart.innerH - (tickVal / chart.maxVal) * chart.innerH;
              return (
                <g key={tickVal}>
                  <line
                    x1={chart.padLeft}
                    y1={y}
                    x2={chart.width - chart.padRight}
                    y2={y}
                    stroke="rgba(255,255,255,0.06)"
                    strokeDasharray="3 4"
                  />
                  <text
                    x={chart.padLeft - 8}
                    y={y + 4}
                    textAnchor="end"
                    className="fill-slate-500 font-mono text-[10px]"
                  >
                    {tickVal}
                  </text>
                </g>
              );
            })}

            {chartMode === 'area' ? (
              <>
                <path d={chart.totalArea} fill="url(#sg-total-grad)" />
                <path d={chart.blockedArea} fill="url(#sg-blocked-grad)" />
                <path
                  d={chart.totalLine}
                  fill="none"
                  stroke="#38BDF8"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  className="sg-path-draw"
                />
                <path
                  d={chart.blockedLine}
                  fill="none"
                  stroke="#F43F5E"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                  className="sg-path-draw"
                />

                {activePoint && (
                  <line
                    x1={activePoint.x}
                    y1={chart.padTop}
                    x2={activePoint.x}
                    y2={chart.bottomY}
                    stroke="rgba(56, 189, 248, 0.35)"
                    strokeWidth="1"
                    strokeDasharray="3 3"
                  />
                )}

                {chart.pts.map((pt) => {
                  const isActive = activePoint?.idx === pt.idx;
                  return (
                    <g key={pt.day}>
                      <circle
                        cx={pt.x}
                        cy={pt.totalY}
                        r={isActive ? 5.5 : 3}
                        fill="#0B101B"
                        stroke="#38BDF8"
                        strokeWidth={isActive ? 2.5 : 2}
                        className="transition-all duration-150"
                      />
                      {pt.blocked > 0 && (
                        <circle
                          cx={pt.x}
                          cy={pt.blockedY}
                          r={isActive ? 5 : 2.5}
                          fill="#F43F5E"
                          stroke="#0B101B"
                          strokeWidth="1.5"
                          className="transition-all duration-150"
                        />
                      )}
                    </g>
                  );
                })}
              </>
            ) : (
              chart.pts.map((pt) => {
                const barW = Math.min(28, Math.max(12, chart.innerW / Math.max(1, chart.pts.length) - 10));
                const blockedH = (pt.blocked / chart.maxVal) * chart.innerH;
                const holdSuspH = ((pt.hold + pt.suspicious) / chart.maxVal) * chart.innerH;
                const safeH = (pt.safe / chart.maxVal) * chart.innerH;
                const isActive = activePoint?.idx === pt.idx;

                return (
                  <g key={pt.day} opacity={hoveredIdx !== null && !isActive ? 0.55 : 1}>
                    {safeH > 0 && (
                      <rect
                        x={pt.x - barW / 2}
                        y={chart.bottomY - blockedH - holdSuspH - safeH}
                        width={barW}
                        height={safeH}
                        rx="2"
                        fill="#34D399"
                        className="sg-bar-grow"
                      />
                    )}
                    {holdSuspH > 0 && (
                      <rect
                        x={pt.x - barW / 2}
                        y={chart.bottomY - blockedH - holdSuspH}
                        width={barW}
                        height={holdSuspH}
                        rx="2"
                        fill="#38BDF8"
                        className="sg-bar-grow"
                      />
                    )}
                    {blockedH > 0 && (
                      <rect
                        x={pt.x - barW / 2}
                        y={chart.bottomY - blockedH}
                        width={barW}
                        height={blockedH}
                        rx="2"
                        fill="#F43F5E"
                        className="sg-bar-grow"
                      />
                    )}
                  </g>
                );
              })
            )}

            {/* Invisible interactive hit zones + X labels */}
            {chart.pts.map((pt, idx) => {
              const stepW = chart.pts.length > 1 ? chart.innerW / (chart.pts.length - 1) : chart.innerW;
              const showLabel = chart.pts.length <= 10 || idx % 2 === 0 || idx === chart.pts.length - 1;
              return (
                <g key={`hit-${pt.day}`}>
                  {showLabel && (
                    <text
                      x={pt.x}
                      y={chart.height - 8}
                      textAnchor="middle"
                      className={`font-mono text-[10px] ${
                        activePoint?.idx === idx ? 'fill-sky-300 font-semibold' : 'fill-slate-500'
                      }`}
                    >
                      {pt.label}
                    </text>
                  )}
                  <rect
                    x={pt.x - stepW / 2}
                    y={chart.padTop}
                    width={stepW}
                    height={chart.innerH + 18}
                    fill="transparent"
                    className="cursor-pointer"
                    onMouseEnter={() => setHoveredIdx(idx)}
                    onClick={() => {
                      if (pt.blocked > 0) onSelectDecision?.('BLOCK');
                      else if (pt.total > 0) onSelectDecision?.('ALL');
                    }}
                  />
                </g>
              );
            })}
          </svg>
        </div>
      )}
    </section>
  );
}

export function VerdictDonutChart({ insights, onSelectDecision }) {
  const [hoveredId, setHoveredId] = useState(null);

  const segments = useMemo(
    () => [
      { id: 'BLOCK', label: 'Blocked', count: insights.blocked, color: '#F43F5E', text: 'text-rose-400' },
      { id: 'SUSPICIOUS', label: 'Suspicious', count: insights.suspicious, color: '#FBBF24', text: 'text-amber-400' },
      { id: 'HOLD', label: 'Hold', count: insights.hold, color: '#38BDF8', text: 'text-sky-400' },
      { id: 'SAFE', label: 'Safe / Cleared', count: insights.safe, color: '#34D399', text: 'text-emerald-400' }
    ],
    [insights]
  );

  const total = Math.max(0, insights.total || 0);
  const radius = 64;
  const circumference = 2 * Math.PI * radius;

  const arcSlices = useMemo(() => {
    if (total === 0) return [];
    let offsetAcc = 0;
    return segments
      .filter((s) => s.count > 0)
      .map((s) => {
        const len = (s.count / total) * circumference;
        const dashOffset = -offsetAcc;
        offsetAcc += len;
        return { ...s, len, dashOffset, pct: Math.round((s.count / total) * 100) };
      });
  }, [segments, total, circumference]);

  const activeSlice = hoveredId ? segments.find((s) => s.id === hoveredId) : null;
  const activePct = activeSlice && total > 0 ? Math.round((activeSlice.count / total) * 100) : null;

  return (
    <section className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-[#101624] p-6 transition-colors hover:border-white/[0.14]">
      <div className="flex items-baseline justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Verdict Ring</h2>
          <p className="mt-0.5 text-xs text-slate-400">Click any segment to filter queue</p>
        </div>
        <span className="font-mono text-xs text-slate-400 tabular-nums">{total} total</span>
      </div>

      <div className="my-5 flex items-center justify-center">
        <div className="relative flex h-44 w-44 items-center justify-center">
          <svg viewBox="0 0 160 160" className="h-full w-full -rotate-90" role="img" aria-label="Verdict distribution ring chart">
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="none"
              stroke="rgba(255,255,255,0.06)"
              strokeWidth="16"
            />
            {arcSlices.map((slice) => {
              const isHovered = hoveredId === slice.id;
              return (
                <circle
                  key={slice.id}
                  cx="80"
                  cy="80"
                  r={radius}
                  fill="none"
                  stroke={slice.color}
                  strokeWidth={isHovered ? 20 : 16}
                  strokeDasharray={`${Math.max(0, slice.len - 2)} ${circumference}`}
                  strokeDashoffset={slice.dashOffset}
                  strokeLinecap="butt"
                  opacity={hoveredId && !isHovered ? 0.4 : 1}
                  className="cursor-pointer transition-all duration-200"
                  onMouseEnter={() => setHoveredId(slice.id)}
                  onMouseLeave={() => setHoveredId(null)}
                  onClick={() => onSelectDecision?.(slice.id)}
                />
              );
            })}
          </svg>

          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className="text-[11px] font-medium text-slate-400">
              {activeSlice ? activeSlice.label : 'All Events'}
            </span>
            <span className="mt-0.5 font-mono text-2xl font-semibold text-slate-50 tabular-nums">
              {activeSlice ? activeSlice.count : total}
            </span>
            <span className="font-mono text-[11px] text-slate-400 tabular-nums">
              {activeSlice ? `${activePct}% share` : `${insights.blocked} blocked`}
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-1">
        {segments.map((seg) => {
          const pct = total > 0 ? Math.round((seg.count / total) * 100) : 0;
          const active = hoveredId === seg.id;
          return (
            <button
              key={seg.id}
              type="button"
              onMouseEnter={() => setHoveredId(seg.id)}
              onMouseLeave={() => setHoveredId(null)}
              onClick={() => onSelectDecision?.(seg.id)}
              className={`flex cursor-pointer items-center justify-between gap-2 rounded-lg border px-3 py-2 text-left transition ${
                active
                  ? 'border-white/[0.2] bg-white/[0.06]'
                  : 'border-white/[0.06] bg-[#0B101B] hover:border-white/[0.14]'
              }`}
            >
              <span className="flex min-w-0 items-center gap-2 text-xs font-medium text-slate-300">
                <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ backgroundColor: seg.color }} />
                <span className="truncate">{seg.label}</span>
              </span>
              <span className={`shrink-0 whitespace-nowrap font-mono text-xs font-semibold tabular-nums ${seg.text}`}>
                {seg.count} ({pct}%)
              </span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

export function RiskDistributionChart({ riskBuckets = [], onSelectRiskBand }) {
  const [hoveredBucket, setHoveredBucket] = useState(null);
  const maxCount = Math.max(1, ...riskBuckets.map((b) => b.count));

  return (
    <section className="flex flex-col justify-between rounded-xl border border-white/[0.08] bg-[#101624] p-6 transition-colors hover:border-white/[0.14]">
      <div className="flex items-baseline justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Risk Score Spectrum</h2>
          <p className="mt-0.5 text-xs text-slate-400">Distribution of 0–100 threat scores</p>
        </div>
        {hoveredBucket && (
          <span className="font-mono text-xs text-slate-300 tabular-nums">
            {hoveredBucket.label}: {hoveredBucket.count} events
          </span>
        )}
      </div>

      <div className="mt-6 grid h-48 grid-cols-4 items-end gap-3 border-b border-white/[0.07] pb-3">
        {riskBuckets.map((bucket) => {
          const heightPct = bucket.count > 0 ? Math.max(12, Math.round((bucket.count / maxCount) * 100)) : 4;
          const isHovered = hoveredBucket?.id === bucket.id;
          return (
            <button
              key={bucket.id}
              type="button"
              onMouseEnter={() => setHoveredBucket(bucket)}
              onMouseLeave={() => setHoveredBucket(null)}
              onClick={() => onSelectRiskBand?.(bucket.id)}
              aria-label={`Filter risk score band ${bucket.label} (${bucket.count} events)`}
              className="group flex h-full cursor-pointer flex-col items-center justify-end gap-1.5 text-center"
            >
              <span className="font-mono text-xs font-semibold text-slate-200 tabular-nums">
                {bucket.count}
              </span>
              <div className="flex h-32 w-full items-end justify-center rounded-lg bg-white/[0.03] px-2 pt-2">
                <div
                  style={{
                    height: `${heightPct}%`,
                    backgroundColor: bucket.color,
                    opacity: bucket.count > 0 ? (isHovered ? 1 : 0.85) : 0.2
                  }}
                  className="sg-bar-grow w-full max-w-[42px] rounded-t-md transition-opacity"
                />
              </div>
              <div className="space-y-0.5">
                <div className="font-mono text-[11px] font-medium text-slate-300">{bucket.label}</div>
                <div className="text-[10px] text-slate-500">{bucket.hint}</div>
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
}

export function SecurityChecksChart({ checkBreakdown = [] }) {
  return (
    <section className="rounded-xl border border-white/[0.08] bg-[#101624] p-6 transition-colors hover:border-white/[0.14]">
      <div className="flex items-baseline justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">On-Device Verification Layer Health</h2>
          <p className="mt-0.5 text-xs text-slate-400">Pass vs Flagged/Failed rates across local checks</p>
        </div>
        <span className="font-mono text-xs text-slate-500 tabular-nums">
          {checkBreakdown.length} layers active
        </span>
      </div>

      {checkBreakdown.length === 0 ? (
        <div className="mt-10 text-center text-xs text-slate-500">
          Security layer telemetry populates once events sync from devices.
        </div>
      ) : (
        <div className="mt-5 space-y-3.5">
          {checkBreakdown.map((ck) => {
            const passPct = ck.total > 0 ? Math.round((ck.passed / ck.total) * 100) : 100;
            const failPct = Math.max(0, 100 - passPct);
            return (
              <div key={ck.key}>
                <div className="flex items-center justify-between gap-3 text-xs">
                  <span className="truncate font-medium text-slate-200">{ck.label}</span>
                  <span className="shrink-0 font-mono text-[11px] text-slate-400 tabular-nums">
                    <span className="text-emerald-400">{ck.passed} passed</span>
                    {ck.failed + ck.flagged > 0 && (
                      <span className="text-rose-400"> · {ck.failed + ck.flagged} flagged/failed</span>
                    )}
                  </span>
                </div>
                <div className="mt-1.5 flex h-2 w-full overflow-hidden rounded-full bg-white/[0.06]">
                  {passPct > 0 && (
                    <div
                      style={{ width: `${passPct}%` }}
                      className="sg-bar-grow-x h-full bg-emerald-400/85"
                    />
                  )}
                  {failPct > 0 && (
                    <div
                      style={{ width: `${failPct}%` }}
                      className="sg-bar-grow-x h-full bg-rose-500/90"
                    />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

export function ScoreRadialGauge({ score = 0, decision = 'HOLD' }) {
  const clamped = Math.min(100, Math.max(0, Number(score) || 0));
  const r = 22;
  const c = 2 * Math.PI * r;
  const offset = c - (clamped / 100) * c;
  const upper = String(decision || '').toUpperCase();
  const color =
    upper === 'BLOCK' || clamped >= 75
      ? '#F43F5E'
      : upper === 'SUSPICIOUS' || clamped >= 50
        ? '#FBBF24'
        : upper === 'HOLD'
          ? '#38BDF8'
          : '#34D399';

  return (
    <div className="relative flex h-14 w-14 shrink-0 items-center justify-center" title={`Risk score ${clamped}/100`}>
      <svg viewBox="0 0 56 56" className="h-full w-full -rotate-90" aria-hidden="true">
        <circle cx="28" cy="28" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="5" />
        <circle
          cx="28"
          cy="28"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="5"
          strokeDasharray={c}
          strokeDashoffset={offset}
          strokeLinecap="round"
        />
      </svg>
      <span className="absolute font-mono text-xs font-semibold text-slate-100 tabular-nums">
        {clamped}
      </span>
    </div>
  );
}
