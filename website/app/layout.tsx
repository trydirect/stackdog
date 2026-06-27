import type { Metadata, Viewport } from 'next';
import { Inter } from 'next/font/google';
import type { ReactNode } from 'react';
import { getSiteUrl } from '@/lib/config';
import Footer from '@/components/Footer';
import Navbar from '@/components/Navbar';
import './globals.css';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap'
});

const defaultDescription =
  'Stackdog Security is a Rust-based security platform for Docker containers and Linux servers with eBPF monitoring, AI-assisted log analysis, threat scoring, and automated response.';

export const metadata: Metadata = {
  metadataBase: new URL(getSiteUrl()),
  title: {
    default: 'Stackdog Security',
    template: '%s | Stackdog Security'
  },
  description: defaultDescription,
  applicationName: 'Stackdog Security',
  keywords: [
    'container security',
    'linux server security',
    'eBPF security monitoring',
    'threat detection',
    'AI security platform',
    'Docker security',
    'Rust security tooling'
  ],
  authors: [{ name: 'Vasili Pascal' }],
  creator: 'Vasili Pascal',
  publisher: 'try.direct',
  alternates: {
    canonical: '/'
  },
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: getSiteUrl(),
    siteName: 'Stackdog Security',
    title: 'Stackdog Security',
    description: defaultDescription
  },
  twitter: {
    card: 'summary_large_image',
    creator: '@VasiliiPascal',
    title: 'Stackdog Security',
    description: defaultDescription
  },
  category: 'technology'
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#020617'
};

interface RootLayoutProps {
  children: ReactNode;
}

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html lang="en" className="bg-slate-950">
      <body className={`${inter.variable} min-h-screen bg-slate-950 font-sans text-slate-100`}>
        <div className="relative flex min-h-screen flex-col overflow-x-hidden">
          <div className="pointer-events-none absolute inset-x-0 top-0 h-[36rem] bg-[radial-gradient(circle_at_top,rgba(6,182,212,0.2),transparent_58%)]" />
          <div className="pointer-events-none absolute right-0 top-24 h-80 w-80 rounded-full bg-violet-500/10 blur-3xl" />
          <Navbar />
          <div className="relative z-10 flex-1">{children}</div>
          <Footer />
        </div>
      </body>
    </html>
  );
}
