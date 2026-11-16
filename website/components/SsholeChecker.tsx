"use client";

import { useMemo, useState } from 'react';

type Platform = 'musl' | 'pam' | 'glibc' | 'unsure';

interface Verdict {
  state: 'affected' | 'patched' | 'not-affected' | 'unknown';
  version: string;
  headline: string;
  detail: string;
}

const FIXED: readonly [number, number, number] = [10, 6, 2];

function parseVersion(input: string): [number, number, number] | null {
  const match = input.match(/(\d+)\.(\d+)(?:[._]?p(\d+))?/);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3] ?? 0)];
}

function check(input: string, platform: Platform): Verdict | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const parsed = parseVersion(trimmed);

  if (platform === 'glibc' || platform === 'pam') {
    return {
      state: 'not-affected',
      version: '',
      headline: 'SSHole does not reach this configuration',
      detail:
        platform === 'pam'
          ? 'SSHole needs passwords checked without PAM. Your sshd checks passwords through PAM, so the oversized-password path is closed.'
          : 'SSHole is specific to musl: glibc-based distributions handle the failed hash differently. This box is not in the affected class.'
    };
  }

  if (!parsed) {
    return {
      state: 'unknown',
      version: '',
      headline: "Couldn't read a version",
      detail: 'Paste the output of ssh -V — it looks like "OpenSSH_10.6p2, OpenSSL ...".'
    };
  }

  const [major, minor, p] = parsed;
  const version = `${major}.${minor}p${p}`;
  const fixed = major > FIXED[0] || (major === FIXED[0] && (minor > FIXED[1] || (minor === FIXED[1] && p >= FIXED[2])));

  if (fixed) {
    return {
      state: 'patched',
      version,
      headline: `${version} carries the fix`,
      detail:
        'SSHole (CVE-2026-123158) was fixed in OpenSSH 10.6p2. Even patched, note that SSHole only ever applied to musl systems with PAM disabled.'
    };
  }

  const unsureNote =
    platform === 'unsure'
      ? ' You said you are unsure about the platform: if this is Alpine or another musl system with the default (no-PAM) OpenSSH, you are affected. Check /etc/os-release and UsePAM in sshd_config.'
      : '';

  return {
    state: 'affected',
    version,
    headline: `${version} predates the SSHole fix`,
    detail: `Upgrade to OpenSSH 10.6p2 — 10.6_p2 on Alpine — and restart sshd. Until then, an oversized password can log an attacker into accounts whose password field is * (root, alpine).${unsureNote}`
  };
}

export default function SsholeChecker() {
  const [input, setInput] = useState('');
  const [platform, setPlatform] = useState<Platform>('musl');
  const verdict = useMemo(() => check(input, platform), [input, platform]);

  const options: { value: Platform; label: string }[] = [
    { value: 'musl', label: 'Alpine / musl, default OpenSSH (no PAM)' },
    { value: 'pam', label: 'OpenSSH checks passwords through PAM' },
    { value: 'glibc', label: 'glibc distro (Debian, Ubuntu, RHEL...)' },
    { value: 'unsure', label: 'Not sure' }
  ];

  return (
    <div className="panel p-6 sm:p-8">
      <label htmlFor="sshole-version-input" className="text-sm font-medium text-slate-200">
        Paste the output of <code>ssh -V</code>
      </label>
      <textarea
        id="sshole-version-input"
        value={input}
        onChange={(event) => setInput(event.target.value)}
        rows={2}
        spellCheck={false}
        placeholder={'OpenSSH_10.5p1, OpenSSL 3.3.2'}
        className="mt-3 w-full rounded-xl border border-slate-700 bg-slate-950/60 px-4 py-3 font-mono text-sm leading-7 text-slate-200 outline-none transition focus:border-cyan-400/60"
      />

      <p className="mt-5 text-sm font-medium text-slate-200">What does this box run?</p>
      <div className="mt-3 grid gap-2">
        {options.map((option) => (
          <label
            key={option.value}
            className={`flex cursor-pointer items-center gap-3 rounded-xl border px-4 py-3 text-sm transition ${
              platform === option.value
                ? 'border-cyan-400/60 bg-cyan-500/10 text-slate-100'
                : 'border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            <input
              type="radio"
              name="sshole-platform"
              value={option.value}
              checked={platform === option.value}
              onChange={() => setPlatform(option.value)}
              className="accent-cyan-400"
            />
            {option.label}
          </label>
        ))}
      </div>

      {verdict && (
        <div
          className={`mt-5 rounded-xl border p-5 ${
            verdict.state === 'patched' || verdict.state === 'not-affected'
              ? 'border-emerald-500/30 bg-emerald-500/10'
              : verdict.state === 'affected'
                ? 'border-amber-500/30 bg-amber-500/10'
                : 'border-slate-700 bg-slate-900/60'
          }`}
        >
          <p
            className={`text-lg font-semibold ${
              verdict.state === 'patched' || verdict.state === 'not-affected'
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
        Checked in your browser; nothing is sent anywhere. This reads only the version string and
        what you select. The same comparison runs for you on every sniff pass as{' '}
        <code>vuln.sshole</code>, on the host and in every running container, and the log half
        watches for the login lines a successful SSHole attack leaves behind.
      </p>
    </div>
  );
}
