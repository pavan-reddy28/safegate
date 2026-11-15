import { useState } from 'react';
import { Eye, EyeOff, Lock, ArrowRight, ShieldCheck, Smartphone, KeyRound } from 'lucide-react';
import { LockerMark } from './LockerMark.jsx';

export function LoginView({ bootstrapState, onLogin }) {
  const [username, setUsername] = useState('pavanreddy');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setErrorMsg('Enter both operator username and password.');
      return;
    }

    setSubmitting(true);
    setErrorMsg('');
    try {
      await onLogin({ username: username.trim(), password });
    } catch (err) {
      setErrorMsg(err?.message || 'Sign-in failed. Verify your credentials.');
    } finally {
      setSubmitting(false);
    }
  };

  const layer1Ready = bootstrapState?.layer1VaultReady !== false;

  const pillars = [
    {
      icon: Smartphone,
      title: 'Zero-Egress On-Device Analysis',
      desc: 'All URL inspection, brand-spoof detection, and ML scoring run locally before telemetry syncs.'
    },
    {
      icon: ShieldCheck,
      title: 'Real-Time Threat Triage',
      desc: 'Review blocked links, inspect 6-layer verification telemetry, and override device verdicts instantly.'
    },
    {
      icon: KeyRound,
      title: 'Dual-Layer Vault Isolation',
      desc: 'Rotating Key Vault bearer credentials remain isolated in server memory with strict cookie binding.'
    }
  ];

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#F8FAFC] px-4 py-10 text-slate-900 sm:px-6 lg:px-10">
      <div
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(#cbd5e1_1px,transparent_1px)] [background-size:24px_24px] opacity-55"
        aria-hidden="true"
      />

      <div className="relative z-10 grid w-full max-w-5xl grid-cols-1 items-stretch gap-8 lg:grid-cols-12">
        {/* Left Architectural Overview */}
        <section className="sg-animate-enter hidden flex-col justify-between rounded-2xl border border-slate-200/90 bg-white p-9 shadow-[0_1px_3px_rgba(15,23,42,0.04)] lg:col-span-7 lg:flex">
          <div>
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-slate-200 bg-slate-50">
                <LockerMark className="h-6 w-6" />
              </div>
              <div>
                <div className="font-display text-lg font-bold tracking-tight text-slate-900">
                  SafeGate Control
                </div>
                <div className="font-mono text-xs text-slate-500">
                  pavanserver.me · Private Security Operations
                </div>
              </div>
            </div>

            <h1 className="mt-8 max-w-lg font-display text-3xl font-bold tracking-tight text-slate-900 [text-wrap:balance]">
              Endpoint Link Verification &amp; Fleet Telemetry
            </h1>
            <p className="mt-3 max-w-lg text-sm leading-relaxed text-slate-600">
              Monitor real-time phishing blocks, inspect multi-layer verification results across enrolled mobile devices, and manage verdict overrides from a single crisp console.
            </p>

            {/* Clean inline architectural flow diagram */}
            <div className="mt-8 rounded-xl border border-slate-200/80 bg-[#F8FAFC] p-5">
              <svg
                viewBox="0 0 540 120"
                className="h-28 w-full"
                role="img"
                aria-label="SafeGate local inspection to operator console pipeline"
              >
                <defs>
                  <linearGradient id="sg-login-flow" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#2563EB" />
                    <stop offset="55%" stopColor="#0284C7" />
                    <stop offset="100%" stopColor="#059669" />
                  </linearGradient>
                </defs>
                <path
                  d="M 85 60 L 245 60 L 455 60"
                  fill="none"
                  stroke="#E2E8F0"
                  strokeWidth="3"
                  strokeLinecap="round"
                />
                <path
                  d="M 85 60 L 245 60 L 455 60"
                  fill="none"
                  stroke="url(#sg-login-flow)"
                  strokeWidth="3"
                  strokeLinecap="round"
                  className="sg-path-draw"
                />

                <g>
                  <rect x="14" y="28" width="136" height="64" rx="12" fill="#FFFFFF" stroke="#CBD5E1" strokeWidth="1.5" />
                  <text x="82" y="54" textAnchor="middle" className="fill-slate-900 font-sans text-[12px] font-semibold">
                    Mobile Device
                  </text>
                  <text x="82" y="74" textAnchor="middle" className="fill-slate-500 font-mono text-[10px]">
                    30-Layer Local Check
                  </text>
                </g>

                <g>
                  <rect x="202" y="28" width="136" height="64" rx="12" fill="#FFFFFF" stroke="#93C5FD" strokeWidth="1.5" />
                  <text x="270" y="54" textAnchor="middle" className="fill-blue-700 font-sans text-[12px] font-semibold">
                    Key Vault BFF
                  </text>
                  <text x="270" y="74" textAnchor="middle" className="fill-slate-500 font-mono text-[10px]">
                    Dual-Layer Session
                  </text>
                </g>

                <g>
                  <rect x="390" y="28" width="136" height="64" rx="12" fill="#FFFFFF" stroke="#6EE7B7" strokeWidth="1.5" />
                  <text x="458" y="54" textAnchor="middle" className="fill-emerald-700 font-sans text-[12px] font-semibold">
                    Operator Triage
                  </text>
                  <text x="458" y="74" textAnchor="middle" className="fill-slate-500 font-mono text-[10px]">
                    Verdict &amp; Audit
                  </text>
                </g>
              </svg>
            </div>
          </div>

          <div className="mt-8 grid grid-cols-1 gap-4 border-t border-slate-100 pt-6 sm:grid-cols-3">
            {pillars.map((item) => {
              const Icon = item.icon;
              return (
                <div key={item.title} className="space-y-1.5">
                  <div className="flex items-center gap-2 text-xs font-semibold text-slate-800">
                    <Icon className="h-4 w-4 shrink-0 text-blue-600" aria-hidden="true" />
                    <span>{item.title}</span>
                  </div>
                  <p className="text-xs leading-relaxed text-slate-500">
                    {item.desc}
                  </p>
                </div>
              );
            })}
          </div>
        </section>

        {/* Right Crisp Sign-In Card */}
        <section className="sg-animate-enter flex flex-col justify-center rounded-2xl border border-slate-200/90 bg-white p-8 shadow-[0_8px_30px_-12px_rgba(15,23,42,0.1)] lg:col-span-5" style={{ animationDelay: '70ms' }}>
          <div className="flex items-center gap-3 lg:hidden">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-slate-200 bg-slate-50">
              <LockerMark className="h-6 w-6" />
            </div>
            <div>
              <h1 className="font-display text-lg font-bold tracking-tight text-slate-900">
                SafeGate Control
              </h1>
              <p className="font-mono text-xs text-slate-500">
                pavanserver.me operator access
              </p>
            </div>
          </div>

          <div className="hidden lg:block">
            <h2 className="font-display text-2xl font-bold tracking-tight text-slate-900">
              Operator Sign In
            </h2>
            <p className="mt-1.5 text-sm text-slate-500">
              Authenticate to inspect telemetry and manage verdict overrides.
            </p>
          </div>

          {!layer1Ready && (
            <div
              role="status"
              className="mt-6 rounded-lg border border-amber-200 bg-amber-50 px-3.5 py-2.5 text-xs font-medium text-amber-800"
            >
              Platform vault token is initializing. Signing in will retry automatically.
            </div>
          )}

          <form onSubmit={handleSubmit} className="mt-7 space-y-5" noValidate>
            <div className="space-y-1.5">
              <label
                htmlFor="operator-username"
                className="block text-xs font-semibold text-slate-700"
              >
                Operator Username
              </label>
              <input
                id="operator-username"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="h-11 w-full rounded-lg border border-slate-200 bg-white px-3.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-600 focus:ring-3 focus:ring-blue-600/15"
                placeholder="pavanreddy"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="operator-password"
                className="block text-xs font-semibold text-slate-700"
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="operator-password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="h-11 w-full rounded-lg border border-slate-200 bg-white pl-3.5 pr-11 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-600 focus:ring-3 focus:ring-blue-600/15"
                  placeholder="Enter operator password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-1.5 top-1/2 flex h-8 w-8 -translate-y-1/2 cursor-pointer items-center justify-center rounded-md text-slate-500 transition hover:bg-slate-100 hover:text-slate-800"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Eye className="h-4 w-4" aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>

            {errorMsg && (
              <div
                role="alert"
                className="rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-xs font-medium text-rose-700"
              >
                {errorMsg}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="flex h-11 w-full cursor-pointer items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 active:scale-[0.99] disabled:cursor-wait disabled:opacity-60"
            >
              <Lock className="h-4 w-4" aria-hidden="true" />
              <span>{submitting ? 'Signing in...' : 'Sign In to Console'}</span>
              {!submitting && <ArrowRight className="h-4 w-4" aria-hidden="true" />}
            </button>
          </form>

          <div className="mt-7 flex items-center justify-between border-t border-slate-100 pt-4 text-xs text-slate-500">
            <span>Single-owner protected access</span>
            <span className="font-mono text-slate-600">pavanserver.me</span>
          </div>
        </section>
      </div>
    </main>
  );
}
