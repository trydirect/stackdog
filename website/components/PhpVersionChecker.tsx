"use client";

import { useMemo, useState } from 'react';

interface Verdict {
  state: 'patched' | 'affected' | 'unknown';
  version: string;
  headline: string;
  detail: string;
}

const FIXED_RELEASES: readonly (readonly [number, number, number])[] = [
  [8, 5, 12],
  [8, 4, 27],
  [8, 3, 36],
  [8, 2, 35]
];

function parseVersion(input: string): [number, number, number] | null {
  const match = input.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3] ?? 0)];
}

function check(input: string): Verdict | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const parsed = parseVersion(trimmed);
  if (!parsed) {
    return {
      state: 'unknown',
      version: '',
      headline: "Couldn't read a version",
      detail: 'Paste the output of php -v — it looks like "PHP 8.3.30 (cli) (built: ...)".'
    };
  }
  const [major, minor, patch] = parsed;
  const version = `${major}.${minor}.${patch}`;

  if (major > 8 || (major === 8 && minor > 5)) {
    return {
      state: 'patched',
      version,
      headline: `${version} is not affected`,
      detail: 'Newer than the last fixed branch (8.5.12). Keep it updated anyway.'
    };
  }

  const fixed = FIXED_RELEASES.find(([fm, fn]) => fm === major && fn === minor);
  if (fixed && patch >= fixed[2]) {
    return {
      state: 'patched',
      version,
      headline: `${version} carries the fix`,
      detail: `PHP2Shell (CVE-2026-109618, CVE-2026-109619) was fixed in ${fixed.join('.')}. Your build is at or above it.`
    };
  }
  if (fixed) {
    const target = fixed.join('.');
    return {
      state: 'affected',
      version,
      headline: `${version} predates the fix`,
      detail: `Upgrade to ${target} or later. The fix is PHP's "avoid state corruption via bailout" (changelog, 22 Oct 2026).`
    };
  }
  return {
    state: 'affected',
    version,
    headline: `${version} gets no fix on this branch`,
    detail: 'The fix shipped on 8.2 and up. Move to 8.2.35, 8.3.36, 8.4.27 or 8.5.12 or later.'
  };
}

export default function PhpVersionChecker() {
  const [input, setInput] = useState('');
  const verdict = useMemo(() => check(input), [input]);

  return (
    <div className="panel p-6 sm:p-8">
      <label htmlFor="php-version-input" className="text-sm font-medium text-slate-200">
        Paste the output of <code>php -v</code>
      </label>
      <textarea
        id="php-version-input"
        value={input}
        onChange={(event) => setInput(event.target.value)}
        rows={3}
        spellCheck={false}
        placeholder={'PHP 8.3.30 (cli) (built: Oct 10 2026 12:00:00) (NTS)'}
        className="mt-3 w-full rounded-xl border border-slate-700 bg-slate-950/60 px-4 py-3 font-mono text-sm leading-7 text-slate-200 outline-none transition focus:border-cyan-400/60"
      />

      {verdict && (
        <div
          className={`mt-5 rounded-xl border p-5 ${
            verdict.state === 'patched'
              ? 'border-emerald-500/30 bg-emerald-500/10'
              : verdict.state === 'affected'
                ? 'border-amber-500/30 bg-amber-500/10'
                : 'border-slate-700 bg-slate-900/60'
          }`}
        >
          <p
            className={`text-lg font-semibold ${
              verdict.state === 'patched'
                ? 'text-emerald-300'
                : verdict.state === 'affected'
                  ? 'text-amber-300'
                  : 'text-slate-200'
            }`}
          >
            {verdict.headline}
          </p>
          <p className="mt-2 text-sm leading-7 text-slate-300">{verdict.detail}</p>
        </div>
      )}

      <p className="mt-5 text-xs leading-6 text-slate-500">
        Checked in your browser; nothing is sent anywhere. This reads only the version string:
        Debian, Ubuntu and Alpine packages may carry a backported fix without changing that
        number — when in doubt, check your vendor&apos;s advisory. Every check here is exactly
        what <code>vuln.php2shell</code> does for you, on your host and in every running
        container, on every sniff pass.
      </p>
    </div>
  );
}
