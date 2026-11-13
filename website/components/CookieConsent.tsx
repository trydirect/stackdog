"use client";

import Script from 'next/script';
import { useEffect, useState } from 'react';

const STORAGE_KEY = 'stackdog-analytics-consent';

type Consent = 'granted' | 'denied';

function readStoredConsent(): Consent | null {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return stored === 'granted' || stored === 'denied' ? stored : null;
  } catch {
    // Private mode or blocked storage: treat as "not decided yet".
    return null;
  }
}

interface CookieConsentProps {
  gaMeasurementId: string;
}

/**
 * Asks before loading Google Analytics, and remembers the answer.
 *
 * The gtag scripts only render once consent is granted, so no analytics
 * cookies are set for visitors who decline or who never answer.
 */
export default function CookieConsent({ gaMeasurementId }: CookieConsentProps) {
  const [consent, setConsent] = useState<Consent | null>(null);
  // Nothing renders until the stored choice is read, so the banner never
  // flashes for visitors who already answered.
  const [resolved, setResolved] = useState(false);

  useEffect(() => {
    setConsent(readStoredConsent());
    setResolved(true);
  }, []);

  function decide(choice: Consent) {
    try {
      window.localStorage.setItem(STORAGE_KEY, choice);
    } catch {
      // Choice still applies for this page view even if it cannot be stored.
    }
    setConsent(choice);
  }

  if (!gaMeasurementId || !resolved) {
    return null;
  }

  if (consent === 'granted') {
    return (
      <>
        <Script
          src={`https://www.googletagmanager.com/gtag/js?id=${gaMeasurementId}`}
          strategy="afterInteractive"
        />
        <Script id="google-analytics" strategy="afterInteractive">
          {`window.dataLayer = window.dataLayer || [];
function gtag(){dataLayer.push(arguments);}
gtag('js', new Date());
gtag('config', '${gaMeasurementId}');`}
        </Script>
      </>
    );
  }

  if (consent === 'denied') {
    return null;
  }

  return (
    <div
      role="dialog"
      aria-live="polite"
      aria-label="Cookie consent"
      className="fixed inset-x-0 bottom-0 z-50 p-4 sm:p-6"
    >
      <div className="panel mx-auto flex max-w-3xl flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
        <p className="text-sm leading-6 text-slate-300">
          We use Google Analytics to understand how the site is used. It sets cookies in your
          browser. Nothing is loaded until you agree.
        </p>
        <div className="flex shrink-0 gap-3">
          <button
            type="button"
            onClick={() => decide('denied')}
            className="rounded-full border border-slate-700 px-5 py-2 text-sm font-semibold text-slate-200 transition hover:border-slate-500 hover:text-white"
          >
            Decline
          </button>
          <button
            type="button"
            onClick={() => decide('granted')}
            className="rounded-full bg-cyan-500 px-5 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
          >
            Accept
          </button>
        </div>
      </div>
    </div>
  );
}
