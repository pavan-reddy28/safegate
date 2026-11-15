import { useEffect, useState } from 'react';
import {
  X,
  Copy,
  Check,
  ShieldCheck,
  ShieldBan,
  PauseCircle,
  AlertTriangle,
  Archive,
  Trash2,
  Save
} from 'lucide-react';
import { formatFullTimestamp, getDecisionStyle, getStatusLabel } from '../utils/insights.js';
import { ScoreRadialGauge } from './InteractiveCharts.jsx';

const DECISION_OPTIONS = ['BLOCK', 'SUSPICIOUS', 'HOLD', 'SAFE', 'KNOWN_SAFE', 'NO_KNOWN_THREAT'];
const STATUS_OPTIONS = ['OPEN', 'REVIEWED', 'RESOLVED', 'ARCHIVED'];
const ACTION_OPTIONS = ['DO_NOT_OPEN', 'WARN_USER', 'HOLD', 'ALLOW', 'ALLOW_WITH_CAUTION'];

export function EventDetailDrawer({
  event,
  onClose,
  onPatchEvent,
  onDeleteEvent
}) {
  const [deviceName, setDeviceName] = useState('');
  const [decision, setDecision] = useState('HOLD');
  const [status, setStatus] = useState('OPEN');
  const [recommendedAction, setRecommendedAction] = useState('HOLD');
  const [score, setScore] = useState(0);
  const [notes, setNotes] = useState('');
  const [copiedId, setCopiedId] = useState(false);
  const [saving, setSaving] = useState(false);
  const [confirmMode, setConfirmMode] = useState(null); // null | 'archive' | 'purge'
  const [feedback, setFeedback] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  useEffect(() => {
    if (!event) return;
    setDeviceName(event.deviceName || '');
    setDecision(event.decision || 'HOLD');
    setStatus(event.status || 'OPEN');
    setRecommendedAction(event.recommendedAction || 'HOLD');
    setScore(Number.isInteger(event.score) ? event.score : 0);
    setNotes(event.notes || '');
  }, [event]);

  useEffect(() => {
    setConfirmMode(null);
    setFeedback('');
    setErrorMsg('');
  }, [event?.requestId]);

  if (!event) return null;

  const decStyle = getDecisionStyle(event.decision);
  const statusStyle = getStatusLabel(event.status);

  const handleCopyRequestId = async () => {
    try {
      await navigator.clipboard.writeText(event.requestId);
      setCopiedId(true);
      window.setTimeout(() => setCopiedId(false), 1600);
    } catch {
      setCopiedId(false);
    }
  };

  const applyQuickVerdict = async (nextDecision, nextStatus, nextAction) => {
    setSaving(true);
    setErrorMsg('');
    setFeedback('');
    try {
      await onPatchEvent(event.requestId, {
        decision: nextDecision,
        status: nextStatus,
        recommendedAction: nextAction
      });
      setDecision(nextDecision);
      setStatus(nextStatus);
      setRecommendedAction(nextAction);
      setFeedback(`Updated to ${nextDecision} (${nextStatus}).`);
    } catch (err) {
      setErrorMsg(err?.message || 'Failed to update verdict.');
    } finally {
      setSaving(false);
    }
  };

  const handleSaveForm = async (e) => {
    e.preventDefault();
    setSaving(true);
    setErrorMsg('');
    setFeedback('');
    try {
      const updates = {
        decision,
        status,
        recommendedAction,
        score: Math.min(100, Math.max(0, Number(score) || 0)),
        notes: notes.trim() ? notes.trim() : null
      };
      if (deviceName.trim()) {
        updates.deviceName = deviceName.trim();
      }
      await onPatchEvent(event.requestId, updates);
      setFeedback('Changes saved to SafeGate database.');
    } catch (err) {
      setErrorMsg(err?.message || 'Failed to save changes.');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteConfirmed = async (archiveOnly) => {
    setSaving(true);
    setErrorMsg('');
    try {
      await onDeleteEvent(event.requestId, { archive: archiveOnly });
      onClose();
    } catch (err) {
      setErrorMsg(err?.message || 'Delete request failed.');
      setSaving(false);
    }
  };

  const securityChecksEntries = Object.entries(event.securityChecks || {});
  const hasUrlInspection = event.urlInspection && Object.keys(event.urlInspection).length > 0;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        className="fixed inset-0 bg-black/70"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside
        aria-label="Event Details Inspector"
        className="sg-drawer-enter relative z-10 flex h-full w-full max-w-2xl flex-col border-l border-white/[0.1] bg-[#0E1422] text-slate-100 shadow-2xl"
      >
        <div className="flex items-center justify-between gap-4 border-b border-white/[0.08] px-6 py-4">
          <div className="flex min-w-0 items-center gap-3.5">
            <ScoreRadialGauge score={event.score} decision={event.decision} />
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <span className={`font-semibold ${decStyle.textClass}`}>{decStyle.label}</span>
                <span aria-hidden="true">·</span>
                <span className={statusStyle.textClass}>{statusStyle.label}</span>
                <span aria-hidden="true">·</span>
                <span className="font-mono tabular-nums">Score {event.score}/100</span>
              </div>
              <div className="mt-1 flex items-center gap-2">
                <h2 className="truncate font-mono text-sm font-semibold text-white">
                  {event.requestId}
                </h2>
                <button
                  type="button"
                  onClick={handleCopyRequestId}
                  aria-label="Copy request ID"
                  className="flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center rounded-md border border-white/[0.1] bg-white/[0.04] text-slate-300 hover:bg-white/[0.08]"
                >
                  {copiedId ? (
                    <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                  ) : (
                    <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close detail inspector"
            className="flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.04] text-slate-300 hover:bg-white/[0.08] hover:text-white"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="flex-1 space-y-6 overflow-y-auto px-6 py-5">
          {feedback && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 text-xs font-medium text-emerald-300">
              {feedback}
            </div>
          )}
          {errorMsg && (
            <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-xs font-medium text-rose-300">
              {errorMsg}
            </div>
          )}

          <div>
            <h3 className="text-xs font-semibold text-slate-400">Quick Verdict Override</h3>
            <div className="mt-2.5 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <button
                type="button"
                disabled={saving}
                onClick={() => applyQuickVerdict('SAFE', 'RESOLVED', 'ALLOW')}
                className="inline-flex h-10 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/12 px-3 text-xs font-semibold text-emerald-200 transition hover:bg-emerald-500/22 disabled:opacity-50 whitespace-nowrap"
              >
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Unblock (Safe)</span>
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => applyQuickVerdict('BLOCK', 'OPEN', 'DO_NOT_OPEN')}
                className="inline-flex h-10 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-rose-500/30 bg-rose-500/12 px-3 text-xs font-semibold text-rose-200 transition hover:bg-rose-500/22 disabled:opacity-50 whitespace-nowrap"
              >
                <ShieldBan className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Block Link</span>
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => applyQuickVerdict('HOLD', 'REVIEWED', 'HOLD')}
                className="inline-flex h-10 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/12 px-3 text-xs font-semibold text-sky-200 transition hover:bg-sky-500/22 disabled:opacity-50 whitespace-nowrap"
              >
                <PauseCircle className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Hold Review</span>
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => applyQuickVerdict('SUSPICIOUS', 'OPEN', 'WARN_USER')}
                className="inline-flex h-10 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/12 px-3 text-xs font-semibold text-amber-200 transition hover:bg-amber-500/22 disabled:opacity-50 whitespace-nowrap"
              >
                <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Suspicious</span>
              </button>
            </div>
          </div>

          <section className="grid grid-cols-1 gap-x-6 gap-y-3 border-y border-white/[0.08] py-4 text-xs sm:grid-cols-2">
            <div>
              <div className="text-slate-500">Device Name</div>
              <div className="mt-0.5 font-medium text-slate-100">{event.deviceName || 'Unlabeled'}</div>
            </div>
            <div>
              <div className="text-slate-500">Device ID</div>
              <div className="mt-0.5 truncate font-mono text-slate-300">{event.deviceId}</div>
            </div>
            <div>
              <div className="text-slate-500">Destination Host / Domain</div>
              <div className="mt-0.5 truncate font-mono text-slate-200">
                {event.destinationHost || 'null'} {event.registrableDomain ? `(${event.registrableDomain})` : ''}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Protocol · Risk · Stage</div>
              <div className="mt-0.5 font-mono text-slate-200">
                {event.protocol || '—'} · {event.riskLevel || '—'} · {event.stage || '—'}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Local Decision · Action</div>
              <div className="mt-0.5 font-mono text-slate-200">
                {event.localDecision || '—'} · {event.recommendedAction || '—'}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Verification · Layers · Egress</div>
              <div className="mt-0.5 font-mono text-slate-200 tabular-nums">
                {event.verificationStatus} · {event.layersExecutedCount} layers · {event.zeroEgress ? 'Zero Egress' : 'Egress'}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Event Time</div>
              <div className="mt-0.5 font-mono text-slate-300 tabular-nums">{formatFullTimestamp(event.eventTime)}</div>
            </div>
            <div>
              <div className="text-slate-500">Updated · App Version</div>
              <div className="mt-0.5 font-mono text-slate-300 tabular-nums">
                {formatFullTimestamp(event.updatedAt)} · v{event.appVersion || '—'}
              </div>
            </div>
          </section>

          <section className="space-y-3">
            <h3 className="text-xs font-semibold text-slate-400">Reasons &amp; Threat Indicators</h3>
            <div className="space-y-2 text-xs">
              <div>
                <span className="text-slate-500">Reasons: </span>
                <span className="font-mono text-slate-200">
                  {Array.isArray(event.reasons) && event.reasons.length ? event.reasons.join(' · ') : 'None'}
                </span>
              </div>
              <div>
                <span className="text-slate-500">Indicators: </span>
                <span className="font-mono text-slate-300">
                  {Array.isArray(event.indicators) && event.indicators.length ? event.indicators.join(' · ') : 'None'}
                </span>
              </div>
            </div>
          </section>

          {securityChecksEntries.length > 0 && (
            <section className="space-y-2.5">
              <h3 className="text-xs font-semibold text-slate-400">On-Device Security Checks</h3>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {securityChecksEntries.map(([key, val]) => {
                  const passed = val === true || val === 'PASSED';
                  const failed = val === 'FAILED' || val === false;
                  return (
                    <div
                      key={key}
                      className="flex items-center justify-between gap-2 rounded-lg border border-white/[0.06] bg-[#0B101B] px-3 py-2 text-xs"
                    >
                      <span className="truncate font-mono text-[11px] text-slate-300">{key}</span>
                      <span
                        className={`shrink-0 font-mono text-[11px] font-semibold ${
                          passed ? 'text-emerald-400' : failed ? 'text-rose-400' : 'text-amber-300'
                        }`}
                      >
                        {String(val)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {hasUrlInspection && (
            <section className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-400">URL Inspection Metrics (Path/Query Redacted)</h3>
              <pre className="overflow-x-auto rounded-lg border border-white/[0.06] bg-[#0B101B] p-3 font-mono text-[11px] text-slate-300">
                {JSON.stringify(event.urlInspection, null, 2)}
              </pre>
            </section>
          )}

          <form onSubmit={handleSaveForm} className="space-y-4 border-t border-white/[0.08] pt-5">
            <h3 className="text-xs font-semibold text-slate-300">Edit Fields &amp; Operator Notes</h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="edit-device-name" className="block text-xs text-slate-400">
                  Device Label
                </label>
                <input
                  id="edit-device-name"
                  type="text"
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-white/[0.1] bg-[#0B101B] px-3 text-xs text-slate-100 outline-none focus:border-sky-400/70"
                  placeholder="Vivo V2355"
                />
              </div>
              <div>
                <label htmlFor="edit-score" className="block text-xs text-slate-400">
                  Risk Score (0-100)
                </label>
                <input
                  id="edit-score"
                  type="number"
                  min={0}
                  max={100}
                  value={score}
                  onChange={(e) => setScore(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-white/[0.1] bg-[#0B101B] px-3 font-mono text-xs text-slate-100 outline-none focus:border-sky-400/70"
                />
              </div>
              <div>
                <label htmlFor="edit-decision" className="block text-xs text-slate-400">
                  Decision
                </label>
                <select
                  id="edit-decision"
                  value={decision}
                  onChange={(e) => setDecision(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-white/[0.1] bg-[#0B101B] px-3 text-xs text-slate-100 outline-none focus:border-sky-400/70"
                >
                  {DECISION_OPTIONS.map((opt) => (
                    <option key={opt} value={opt}>{opt}</option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="edit-status" className="block text-xs text-slate-400">
                  Status
                </label>
                <select
                  id="edit-status"
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-white/[0.1] bg-[#0B101B] px-3 text-xs text-slate-100 outline-none focus:border-sky-400/70"
                >
                  {STATUS_OPTIONS.map((opt) => (
                    <option key={opt} value={opt}>{opt}</option>
                  ))}
                </select>
              </div>
              <div className="sm:col-span-2">
                <label htmlFor="edit-action" className="block text-xs text-slate-400">
                  Recommended Action
                </label>
                <select
                  id="edit-action"
                  value={recommendedAction}
                  onChange={(e) => setRecommendedAction(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-white/[0.1] bg-[#0B101B] px-3 text-xs text-slate-100 outline-none focus:border-sky-400/70"
                >
                  {ACTION_OPTIONS.map((opt) => (
                    <option key={opt} value={opt}>{opt}</option>
                  ))}
                </select>
              </div>
              <div className="sm:col-span-2">
                <label htmlFor="edit-notes" className="block text-xs text-slate-400">
                  Operator Notes
                </label>
                <textarea
                  id="edit-notes"
                  rows={2}
                  maxLength={500}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Optional investigation note (no raw URLs or PII)"
                  className="mt-1 w-full rounded-lg border border-white/[0.1] bg-[#0B101B] p-3 text-xs text-slate-100 outline-none focus:border-sky-400/70"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
              <button
                type="submit"
                disabled={saving}
                className="inline-flex h-10 cursor-pointer items-center gap-2 rounded-lg bg-sky-500 px-4 text-xs font-semibold text-slate-950 transition hover:bg-sky-400 disabled:opacity-50 whitespace-nowrap"
              >
                <Save className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{saving ? 'Saving...' : 'Save Changes'}</span>
              </button>

              {confirmMode === null ? (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={saving}
                    onClick={() => setConfirmMode('archive')}
                    className="inline-flex h-10 cursor-pointer items-center gap-1.5 rounded-lg border border-white/[0.1] bg-white/[0.04] px-3 text-xs font-medium text-slate-300 hover:bg-white/[0.08] whitespace-nowrap"
                  >
                    <Archive className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Archive</span>
                  </button>
                  <button
                    type="button"
                    disabled={saving}
                    onClick={() => setConfirmMode('purge')}
                    className="inline-flex h-10 cursor-pointer items-center gap-1.5 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 text-xs font-medium text-rose-300 hover:bg-rose-500/20 whitespace-nowrap"
                  >
                    <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Delete Permanently</span>
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-2 rounded-lg border border-rose-500/35 bg-rose-500/10 px-3 py-1.5 text-xs">
                  <span className="text-rose-200">
                    {confirmMode === 'archive' ? 'Archive record?' : 'Permanently delete from DB?'}
                  </span>
                  <button
                    type="button"
                    disabled={saving}
                    onClick={() => handleDeleteConfirmed(confirmMode === 'archive')}
                    className="cursor-pointer rounded bg-rose-600 px-2.5 py-1 font-semibold text-white hover:bg-rose-500 whitespace-nowrap"
                  >
                    Confirm
                  </button>
                  <button
                    type="button"
                    disabled={saving}
                    onClick={() => setConfirmMode(null)}
                    className="cursor-pointer px-2 py-1 text-slate-300 hover:text-white whitespace-nowrap"
                  >
                    Cancel
                  </button>
                </div>
              )}
            </div>
          </form>
        </div>
      </aside>
    </div>
  );
}
