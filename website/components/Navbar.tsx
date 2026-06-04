"use client";

import Link from 'next/link';
import Image from 'next/image';
import { usePathname } from 'next/navigation';
import { ExternalLink, Menu, X } from 'lucide-react';
import { useMemo, useState } from 'react';

interface NavbarProps {}

interface NavItem {
  href: string;
  label: string;
}

const navItems: NavItem[] = [
  { href: '/', label: 'Home' },
  { href: '/docs', label: 'Docs' },
  { href: '/contact', label: 'Contact' }
];

export default function Navbar(_: NavbarProps) {
  const pathname = usePathname();
  const [isOpen, setIsOpen] = useState(false);

  const activePath = useMemo(() => pathname ?? '/', [pathname]);

  const linkClassName = (href: string) => {
    const isActive = href === '/' ? activePath === href : activePath.startsWith(href);

    return [
      'rounded-full px-4 py-2 text-sm font-medium transition-colors',
      isActive ? 'bg-cyan-500/10 text-cyan-300' : 'text-slate-300 hover:text-white'
    ].join(' ');
  };

  return (
    <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-slate-950/85 backdrop-blur-xl">
      <div className="site-container">
        <nav className="flex h-16 items-center justify-between gap-4 py-4" aria-label="Primary navigation">
          <Link href="/" className="inline-flex items-center gap-2.5 text-white" aria-label="Stackdog Security home">
            <span className="flex h-9 w-9 items-center justify-center rounded-full bg-white p-1">
              <Image
                src="/stackdog-mark.png"
                alt="Stackdog mark"
                width={28}
                height={28}
                className="h-7 w-7"
                priority
              />
            </span>
            <span className="text-lg font-bold tracking-tight">
              STACK<span className="text-orange-500">DOG</span>
            </span>
          </Link>

          <div className="hidden items-center gap-2 md:flex">
            {navItems.map((item) => (
              <Link key={item.href} href={item.href} className={linkClassName(item.href)}>
                {item.label}
              </Link>
            ))}
            <a
              href="https://github.com/trydirect/stackdog"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:border-cyan-400/60 hover:text-white"
              aria-label="View Stackdog on GitHub"
            >
              GitHub
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>

          <button
            type="button"
            className="inline-flex items-center justify-center rounded-full border border-slate-700 p-2 text-slate-200 md:hidden"
            onClick={() => setIsOpen((current) => !current)}
            aria-expanded={isOpen}
            aria-controls="mobile-navigation"
            aria-label={isOpen ? 'Close navigation menu' : 'Open navigation menu'}
          >
            {isOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </nav>

        {isOpen ? (
          <div id="mobile-navigation" className="pb-4 md:hidden">
            <div className="panel flex flex-col gap-2 p-3">
              {navItems.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className={linkClassName(item.href)}
                  onClick={() => setIsOpen(false)}
                >
                  {item.label}
                </Link>
              ))}
              <a
                href="https://github.com/trydirect/stackdog"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center justify-between rounded-full border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200"
                aria-label="Open GitHub repository in a new tab"
              >
                GitHub
                <ExternalLink className="h-4 w-4" />
              </a>
            </div>
          </div>
        ) : null}
      </div>
    </header>
  );
}
