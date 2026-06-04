import type { Metadata } from 'next';
import { Code2, Mail, ShieldCheck } from 'lucide-react';

function DiscordIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
      <path d="M20.317 4.492c-1.53-.69-3.17-1.2-4.885-1.49a.075.075 0 0 0-.079.036c-.21.369-.444.85-.608 1.23a18.566 18.566 0 0 0-5.487 0 12.36 12.36 0 0 0-.617-1.23A.077.077 0 0 0 8.562 3c-1.714.29-3.354.8-4.885 1.491a.07.07 0 0 0-.032.027C.533 9.093-.32 13.555.099 17.961a.08.08 0 0 0 .031.055 20.03 20.03 0 0 0 5.993 2.98.078.078 0 0 0 .084-.026 13.83 13.83 0 0 0 1.226-1.963.074.074 0 0 0-.041-.104 13.175 13.175 0 0 1-1.872-.878.075.075 0 0 1-.008-.125c.126-.093.252-.19.372-.287a.075.075 0 0 1 .078-.01c3.927 1.764 8.18 1.764 12.061 0a.075.075 0 0 1 .079.009c.12.098.245.195.372.288a.075.075 0 0 1-.006.125c-.598.344-1.22.635-1.873.877a.075.075 0 0 0-.041.105c.36.687.772 1.341 1.225 1.962a.077.077 0 0 0 .084.028 19.963 19.963 0 0 0 6.002-2.981.076.076 0 0 0 .032-.054c.5-5.094-.838-9.52-3.549-13.442a.06.06 0 0 0-.031-.028zM8.02 15.278c-1.182 0-2.157-1.069-2.157-2.38 0-1.312.956-2.38 2.157-2.38 1.21 0 2.176 1.077 2.157 2.38 0 1.312-.956 2.38-2.157 2.38zm7.975 0c-1.183 0-2.157-1.069-2.157-2.38 0-1.312.955-2.38 2.157-2.38 1.21 0 2.176 1.077 2.157 2.38 0 1.312-.946 2.38-2.157 2.38z" />
    </svg>
  );
}
import ContactForm from '@/components/ContactForm';

export const metadata: Metadata = {
  title: 'Contact',
  description:
    'Contact Stackdog Security for enterprise questions, security reports, partnership conversations, or product feedback.',
  keywords: ['contact Stackdog', 'Stackdog enterprise', 'security disclosure', 'Stackdog support'],
  alternates: {
    canonical: '/contact'
  },
  openGraph: {
    title: 'Contact Stackdog Security',
    description:
      'Reach the Stackdog team for demos, enterprise evaluations, and responsible security disclosures.',
    url: 'https://stackdog.io/contact'
  },
  twitter: {
    title: 'Contact Stackdog Security',
    description:
      'Reach the Stackdog team for demos, enterprise evaluations, and responsible security disclosures.'
  }
};

const contactLinks = [
  {
    title: 'Email',
    value: 'info@try.direct',
    href: 'mailto:info@try.direct',
    icon: Mail
  },
  {
    title: 'GitHub',
    value: 'trydirect/stackdog',
    href: 'https://github.com/trydirect/stackdog',
    icon: Code2
  },
  {
    title: 'Discord',
    value: 'Join our community',
    href: 'https://discord.gg/RVCcA8QZ9m',
    icon: DiscordIcon
  }
];

export default function ContactPage() {
  return (
    <main className="section-shell pt-12 sm:pt-16">
      <div className="site-container">
        <div className="max-w-3xl">
          <span className="eyebrow">Talk to the Stackdog team</span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight text-white sm:text-5xl">
            Bring runtime security to your infrastructure without extra drag
          </h1>
          <p className="mt-6 text-lg leading-8 text-slate-400">
            Reach out for enterprise deployments, responsible disclosure, roadmap conversations, or
            implementation guidance around Docker and Linux server security.
          </p>
        </div>

        <div className="mt-12 grid gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:items-start">
          <section className="space-y-6">
            <article className="panel p-6">
              <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <h2 className="mt-5 text-2xl font-semibold text-white">What can we help with?</h2>
              <ul className="mt-4 space-y-3 text-sm leading-7 text-slate-400">
                <li>Enterprise security evaluations and architecture reviews</li>
                <li>Security reports and responsible disclosure follow-up</li>
                <li>Feature requests, roadmap discussions, and integrations</li>
                <li>Hands-on support with alert routing and response automation</li>
              </ul>
            </article>

            <div className="grid gap-4 sm:grid-cols-3 lg:grid-cols-1">
              {contactLinks.map((entry) => {
                const Icon = entry.icon;
                return (
                  <a
                    key={entry.title}
                    href={entry.href}
                    target={entry.href.startsWith('http') ? '_blank' : undefined}
                    rel={entry.href.startsWith('http') ? 'noreferrer' : undefined}
                    className="panel flex items-center gap-4 p-5 transition hover:border-cyan-400/50"
                  >
                    <span className="inline-flex h-11 w-11 items-center justify-center rounded-2xl border border-slate-700 bg-slate-950/70 text-cyan-300">
                      <Icon className="h-5 w-5" />
                    </span>
                    <span>
                      <span className="block text-sm font-medium text-slate-200">{entry.title}</span>
                      <span className="mt-1 block text-sm text-slate-400">{entry.value}</span>
                    </span>
                  </a>
                );
              })}
            </div>
          </section>

          <section aria-labelledby="contact-form-heading">
            <div className="mb-5">
              <h2 id="contact-form-heading" className="text-2xl font-semibold text-white">
                Send a message
              </h2>
              <p className="mt-3 text-sm leading-7 text-slate-400">
                Messages are delivered through a secure webhook flow so the team can pick them up in
                Slack quickly.
              </p>
            </div>
            <ContactForm />
          </section>
        </div>
      </div>
    </main>
  );
}
