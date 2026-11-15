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
      setFeedback(`Updated to ${nextDecision} (${nextStatus}) — active on device sync.`);
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
      setFeedback('Changes saved — active on device policy sync.');
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
        className="fixed inset-0 bg-slate-900/35 backdrop-blur-[2px]"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside
        aria-label="Event Details Inspector"
        className="sg-drawer-enter relative z-10 flex h-full w-full max-w-2xl flex-col border-l border-slate-200 bg-white text-slate-900 shadow-2xl"
      >
        <div className="flex items-center justify-between gap-4 border-b border-slate-200 px-6 py-4">
          <div className="flex min-w-0 items-center gap-3.5">
            <ScoreRadialGauge score={event.score} decision={event.decision} />
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <span className={`font-semibold ${decStyle.textClass}`}>{decStyle.label}</span>
                <span aria-hidden="true">·</span>
                <span className={`font-medium ${statusStyle.textClass}`}>{statusStyle.label}</span>
                <span aria-hidden="true">·</span>
                <span className="font-mono tabular-nums">Score {event.score}/100</span>
              </div>
              <div className="mt-1 flex items-center gap-2">
                <h2 className="truncate font-mono text-sm font-bold text-slate-900">
                  {event.requestId}
                </h2>
                <button
                  type="button"
                  onClick={handleCopyRequestId}
                  aria-label="Copy request ID"
                  className="flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center rounded-md border border-slate-200 bg-slate-50 text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
                >
                  {copiedId ? (
                    <Check className="h-3.5 w-3.5 text-emerald-600" aria-hidden="true" />
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
            className="flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-500 transition hover:bg-slate-100 hover:text-slate-900"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="flex-1 space-y-6 overflow-y-auto px-6 py-5">
          {feedback && (
            <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-2.5 text-xs font-medium text-emerald-800">
              {feedback}
            </div>
          )}
          {errorMsg && (
            <div role="alert" className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-2.5 text-xs font-medium text-rose-700">
              {errorMsg}
            </div>
          )}

          <div>
            <h3 className="text-xs font-semibold text-slate-500">Quick Verdict Override</h3>
            <div className="mt-2.5 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <button
                type="button"
                disabled={saving}
                onClick={() => applyQuickVerdict('SAFE', 'RESOLVED', 'ALLOW')}
                className="inline-flex h-10 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-emerald-200 bg-emerald-50 px-3 text-xs font-semibold text-emerald-700 transition hover:bg-emerald-100 disabled:opacity-50 whitespace-nowrap"
              >
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Unblock (Safe)</span>
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => applyQuickVerdict('BLOCK', 'OPEN', 'DO_NOT_OPEN')}
                className="inline-flex h-10 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-rose-200 bg-rose-50 px-3 text-xs font-semibold text-rose-700 transition hover:bg-rose-100 disabled:opacity-50 whitespace-nowrap"
              >
                <ShieldBan className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Block Link</span>
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => applyQuickVerdict('HOLD', 'REVIEWED', 'HOLD')}
                className="inline-flex h-10 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-sky-200 bg-sky-50 px-3 text-xs font-semibold text-sky-700 transition hover:bg-sky-100 disabled:opacity-50 whitespace-nowrap"
              >
                <PauseCircle className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Hold Review</span>
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => applyQuickVerdict('SUSPICIOUS', 'OPEN', 'WARN_USER')}
                className="inline-flex h-10 cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-amber-200 bg-amber-50 px-3 text-xs font-semibold text-amber-800 transition hover:bg-amber-100 disabled:opacity-50 whitespace-nowrap"
              >
                <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Suspicious</span>
              </button>
            </div>
          </div>

          <section className="grid grid-cols-1 gap-x-6 gap-y-3 border-y border-slate-200/80 py-4 text-xs sm:grid-cols-2">
            <div>
              <div className="text-slate-500">Device Name</div>
              <div className="mt-0.5 font-semibold text-slate-900">{event.deviceName || 'Unlabeled'}</div>
            </div>
            <div>
              <div className="text-slate-500">Device ID</div>
              <div className="mt-0.5 truncate font-mono text-slate-700">{event.deviceId}</div>
            </div>
            <div>
              <div className="text-slate-500">Destination Host / Domain</div>
              <div className="mt-0.5 truncate font-mono text-slate-800">
                {event.destinationHost || 'null'} {event.registrableDomain ? `(${event.registrableDomain})` : ''}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Protocol · Risk · Stage</div>
              <div className="mt-0.5 font-mono text-slate-800">
                {event.protocol || '—'} · {event.riskLevel || '—'} · {event.stage || '—'}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Local Decision · Action</div>
              <div className="mt-0.5 font-mono text-slate-800">
                {event.localDecision || '—'} · {event.recommendedAction || '—'}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Verification · Layers · Egress</div>
              <div className="mt-0.5 font-mono text-slate-800 tabular-nums">
                {event.verificationStatus} · {event.layersExecutedCount} layers · {event.zeroEgress ? 'Zero Egress' : 'Egress'}
              </div>
            </div>
            <div>
              <div className="text-slate-500">Event Time</div>
              <div className="mt-0.5 font-mono text-slate-700 tabular-nums">{formatFullTimestamp(event.eventTime)}</div>
            </div>
            <div>
              <div className="text-slate-500">Updated · App Version</div>
              <div className="mt-0.5 font-mono text-slate-700 tabular-nums">
                {formatFullTimestamp(event.updatedAt)} · v{event.appVersion || '—'}
              </div>
            </div>
          </section>

          <section className="space-y-3">
            <h3 className="text-xs font-semibold text-slate-500">Reasons &amp; Threat Indicators</h3>
            <div className="space-y-2 text-xs">
              <div>
                <span className="text-slate-500">Reasons: </span>
                <span className="font-mono text-slate-900">
                  {Array.isArray(event.reasons) && event.reasons.length ? event.reasons.join(' · ') : 'None'}
                </span>
              </div>
              <div>
                <span className="text-slate-500">Indicators: </span>
                <span className="font-mono text-slate-700">
                  {Array.isArray(event.indicators) && event.indicators.length ? event.indicators.join(' · ') : 'None'}
                </span>
              </div>
            </div>
          </section>

          {securityChecksEntries.length > 0 && (
            <section className="space-y-2.5">
              <h3 className="text-xs font-semibold text-slate-500">On-Device Security Checks</h3>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {securityChecksEntries.map(([key, val]) => {
                  const passed = val === true || val === 'PASSED';
                  const failed = val === 'FAILED' || val === false;
                  return (
                    <div
                      key={key}
                      className="flex items-center justify-between gap-2 rounded-lg border border-slate-200/80 bg-[#F8FAFC] px-3 py-2 text-xs"
                    >
                      <span className="truncate font-mono text-[11px] text-slate-700">{key}</span>
                      <span
                        className={`shrink-0 font-mono text-[11px] font-semibold ${
                          passed ? 'text-emerald-600' : failed ? 'text-rose-600' : 'text-amber-600'
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
              <h3 className="text-xs font-semibold text-slate-500">URL Inspection Metrics (Path/Query Redacted)</h3>
              <pre className="overflow-x-auto rounded-lg border border-slate-200/80 bg-[#F8FAFC] p-3 font-mono text-[11px] text-slate-800">
                {JSON.stringify(event.urlInspection, null, 2)}
              </pre>
            </section>
          )}

          <form onSubmit={handleSaveForm} className="space-y-4 border-t border-slate-200/80 pt-5">
            <h3 className="text-xs font-semibold text-slate-700">Edit Fields &amp; Operator Notes</h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="edit-device-name" className="block text-xs font-medium text-slate-600">
                  Device Label
                </label>
                <input
                  id="edit-device-name"
                  type="text"
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-slate-200 bg-white px-3 text-xs text-slate-900 outline-none focus:border-blue-600"
                  placeholder="Vivo V2355"
                />
              </div>
              <div>
                <label htmlFor="edit-score" className="block text-xs font-medium text-slate-600">
                  Risk Score (0-100)
                </label>
                <input
                  id="edit-score"
                  type="number"
                  min={0}
                  max={100}
                  value={score}
                  onChange={(e) => setScore(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-slate-200 bg-white px-3 font-mono text-xs text-slate-900 outline-none focus:border-blue-600"
                />
              </div>
              <div>
                <label htmlFor="edit-decision" className="block text-xs font-medium text-slate-600">
                  Decision
                </label>
                <select
                  id="edit-decision"
                  value={decision}
                  onChange={(e) => setDecision(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-slate-200 bg-white px-3 text-xs text-slate-900 outline-none focus:border-blue-600"
                >
                  {DECISION_OPTIONS.map((opt) => (
                    <option key={opt} value={opt}>{opt}</option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="edit-status" className="block text-xs font-medium text-slate-600">
                  Status
                </label>
                <select
                  id="edit-status"
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-slate-200 bg-white px-3 text-xs text-slate-900 outline-none focus:border-blue-600"
                >
                  {STATUS_OPTIONS.map((opt) => (
                    <option key={opt} value={opt}>{opt}</option>
                  ))}
                </select>
              </div>
              <div className="sm:col-span-2">
                <label htmlFor="edit-action" className="block text-xs font-medium text-slate-600">
                  Recommended Action
                </label>
                <select
                  id="edit-action"
                  value={recommendedAction}
                  onChange={(e) => setRecommendedAction(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-slate-200 bg-white px-3 text-xs text-slate-900 outline-none focus:border-blue-600"
                >
                  {ACTION_OPTIONS.map((opt) => (
                    <option key={opt} value={opt}>{opt}</option>
                  ))}
                </select>
              </div>
              <div className="sm:col-span-2">
                <label htmlFor="edit-notes" className="block text-xs font-medium text-slate-600">
                  Operator Notes
                </label>
                <textarea
                  id="edit-notes"
                  rows={2}
                  maxLength={500}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Optional investigation note (no raw URLs or PII)"
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white p-3 text-xs text-slate-900 outline-none focus:border-blue-600"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
              <button
                type="submit"
                disabled={saving}
                className="inline-flex h-10 cursor-pointer items-center gap-2 rounded-lg bg-blue-600 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap"
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
                    className="inline-flex h-10 cursor-pointer items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 text-xs font-semibold text-slate-700 transition hover:bg-slate-50 whitespace-nowrap"
                  >
                    <Archive className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Archive</span>
                  </button>
                  <button
                    type="button"
                    disabled={saving}
                    onClick={() => setConfirmMode('purge')}
                    className="inline-flex h-10 cursor-pointer items-center gap-1.5 rounded-lg border border-rose-200 bg-rose-50 px-3 text-xs font-semibold text-rose-700 transition hover:bg-rose-100 whitespace-nowrap"
                  >
                    <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Delete Permanently</span>
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-2 rounded-lg border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs">
                  <span className="font-medium text-rose-800">
                    {confirmMode === 'archive' ? 'Archive record?' : 'Permanently delete from DB?'}
                  </span>
                  <button
                    type="button"
                    disabled={saving}
                    onClick={() => handleDeleteConfirmed(confirmMode === 'archive')}
                    className="cursor-pointer rounded bg-rose-600 px-2.5 py-1 font-semibold text-white hover:bg-rose-700 whitespace-nowrap"
                  >
                    Confirm
                  </button>
                  <button
                    type="button"
                    disabled={saving}
                    onClick={() => setConfirmMode(null)}
                    className="cursor-pointer px-2 py-1 font-medium text-slate-600 hover:text-slate-900 whitespace-nowrap"
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
