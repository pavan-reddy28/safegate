import { useState } from 'react';
import { Eye, EyeOff, Lock, ArrowRight } from 'lucide-react';
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

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#090D16] px-4 py-12 text-slate-100">
      <div className="w-full max-w-[400px] rounded-2xl border border-white/[0.08] bg-[#101624] p-8">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-white/[0.08] bg-[#0B101B]">
            <LockerMark className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-slate-50">
              SafeGate Control
            </h1>
            <p className="text-xs text-slate-400">
              pavanserver.me operator access
            </p>
          </div>
        </div>

        {!layer1Ready && (
          <div
            role="status"
            className="mt-6 rounded-lg border border-amber-500/25 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-300"
          >
            Platform vault token is initializing. Signing in will retry automatically.
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-7 space-y-5" noValidate>
          <div className="space-y-1.5">
            <label
              htmlFor="operator-username"
              className="block text-xs font-medium text-slate-300"
            >
              Operator Username
            </label>
            <input
              id="operator-username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-lg border border-white/[0.1] bg-[#0B101B] px-3.5 py-2.5 text-sm text-slate-100 outline-none transition focus:border-sky-400/70 focus:ring-2 focus:ring-sky-400/20"
              placeholder="pavanreddy"
            />
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="operator-password"
              className="block text-xs font-medium text-slate-300"
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
                className="w-full rounded-lg border border-white/[0.1] bg-[#0B101B] py-2.5 pl-3.5 pr-11 text-sm text-slate-100 outline-none transition focus:border-sky-400/70 focus:ring-2 focus:ring-sky-400/20"
                placeholder="Enter operator password"
              />
              <button
                type="button"
                onClick={() => setShowPassword((prev) => !prev)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                className="absolute right-1.5 top-1/2 flex h-8 w-8 -translate-y-1/2 cursor-pointer items-center justify-center rounded-md text-slate-400 transition hover:bg-white/[0.06] hover:text-slate-200"
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
              className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3.5 py-2.5 text-xs font-medium text-rose-300"
            >
              {errorMsg}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="flex h-11 w-full cursor-pointer items-center justify-center gap-2 rounded-lg bg-sky-500 px-4 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 active:scale-[0.99] disabled:cursor-wait disabled:opacity-60"
          >
            <Lock className="h-4 w-4" aria-hidden="true" />
            <span>{submitting ? 'Signing in...' : 'Sign In'}</span>
            {!submitting && <ArrowRight className="h-4 w-4" aria-hidden="true" />}
          </button>
        </form>

        <div className="mt-6 flex items-center justify-between border-t border-white/[0.07] pt-4 text-xs text-slate-500">
          <span>Dual-layer token protection</span>
          <span className="font-mono">pavanserver.me</span>
        </div>
      </div>
    </main>
  );
}
