import React, { useEffect, useState } from 'react';
import logoUrl from '../assets/logo.png';
import './Sidebar.css';

const links = [
  { id: 'overview', label: 'Overview', path: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z' },
  { id: 'threat-map', label: 'Threat Map', path: 'M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Z M7 12h3l2-4 2 8 2-4h2' },
  { id: 'alerts', label: 'Alerts', path: 'M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9 M10 21h4' },
  { id: 'containers', label: 'Containers', path: 'm12 3 9 5v9l-9 5-9-5V8l9-5Z M3 8l9 5 9-5 M12 13v9 M7.5 5.5l9 5' },
];

const sectionFromHash = () => {
  const hash = window.location.hash.split('/')[0] || '#overview';
  return hash === '#threats' ? '#threat-map' : hash;
};

const Sidebar: React.FC = () => {
  const [activeSection, setActiveSection] = useState(sectionFromHash);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    const updateFromScroll = () => {
      const sections = links.map(({ id }) => document.getElementById(id))
        .filter((section): section is HTMLElement => section !== null);
      if (!sections.length) return;

      const atBottom = window.scrollY > 0 &&
        Math.ceil(window.scrollY + window.innerHeight) >= document.documentElement.scrollHeight;
      const section = atBottom
        ? sections[sections.length - 1]
        : [...sections].reverse().find(item => item.getBoundingClientRect().top <= 96) || sections[0];
      setActiveSection(`#${section.id}`);
    };
    const updateFromHash = () => setActiveSection(sectionFromHash());
    // Dashboard sections arrive after the API response; their heights also
    // change when alerts and containers finish loading or filters are applied.
    const observer = new ResizeObserver(updateFromScroll);
    observer.observe(document.body);
    window.addEventListener('scroll', updateFromScroll, { passive: true });
    window.addEventListener('resize', updateFromScroll);
    window.addEventListener('hashchange', updateFromHash);
    updateFromScroll();

    return () => {
      observer.disconnect();
      window.removeEventListener('scroll', updateFromScroll);
      window.removeEventListener('resize', updateFromScroll);
      window.removeEventListener('hashchange', updateFromHash);
    };
  }, []);

  const navigateToSection = (event: React.MouseEvent<HTMLAnchorElement>, id: string) => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const section = document.getElementById(id);
    if (!section) return;
    event.preventDefault();
    const hash = `#${id}`;
    if (window.location.hash !== hash) window.history.pushState(null, '', hash);
    setActiveSection(hash);
    section.scrollIntoView({
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
      block: 'start',
    });
  };

  return (
    <aside className={`sidebar${collapsed ? ' sidebar-collapsed' : ''}`}>
      <div className="sidebar-brand" title="Stackdog">
        <img
          src={logoUrl}
          alt="Stackdog logo"
          className="sidebar-logo"
          width={39}
          height={39}
        />
        <span className="sidebar-brand-title">Stackdog</span>
      </div>
      <nav id="sidebar-navigation" className="sidebar-nav" aria-label="Main navigation">
        {links.map(({ id, label, path }) => (
          <a key={id} href={`#${id}`} title={label} aria-label={label} aria-current={activeSection === `#${id}` ? 'location' : undefined} onClick={(event) => navigateToSection(event, id)}>
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d={path} />
            </svg>
            <span className="sidebar-link-label">{label}</span>
          </a>
        ))}
      </nav>
      <button
        type="button"
        className="sidebar-toggle"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        aria-expanded={!collapsed}
        aria-controls="sidebar-navigation"
        onClick={() => setCollapsed(value => !value)}
      >
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d={collapsed ? 'm9 6 6 6-6 6' : 'm15 6-6 6 6 6'} />
        </svg>
        <span className="sidebar-link-label">Collapse sidebar</span>
      </button>
    </aside>
  );
};

export default Sidebar;
