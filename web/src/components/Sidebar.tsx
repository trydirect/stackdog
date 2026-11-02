import React, { useEffect, useState } from 'react';
import logoUrl from '../assets/logo.png';
import './Sidebar.css';

const Sidebar: React.FC = () => {
  const [activeSection, setActiveSection] = useState(window.location.hash.split('/')[0] || '#overview');

  useEffect(() => {
    const updateSection = () => setActiveSection(window.location.hash.split('/')[0] || '#overview');
    window.addEventListener('hashchange', updateSection);
    return () => window.removeEventListener('hashchange', updateSection);
  }, []);

  const links = [
    { id: 'overview', label: 'Overview', path: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z' },
    { id: 'threats', label: 'Threat Map', path: 'M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Z M7 12h3l2-4 2 8 2-4h2' },
    { id: 'alerts', label: 'Alerts', path: 'M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9 M10 21h4' },
    { id: 'containers', label: 'Containers', path: 'm12 3 9 5v9l-9 5-9-5V8l9-5Z M3 8l9 5 9-5 M12 13v9 M7.5 5.5l9 5' },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <img
          src={logoUrl}
          alt="Stackdog logo"
          className="sidebar-logo"
          width={39}
          height={39}
        />
        <span>Stackdog</span>
      </div>
      <nav className="sidebar-nav" aria-label="Main navigation">
        {links.map(({ id, label, path }) => (
          <a key={id} href={`#${id}`} aria-current={activeSection === `#${id}` ? 'location' : undefined}>
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d={path} />
            </svg>
            {label}
          </a>
        ))}
      </nav>
    </aside>
  );
};

export default Sidebar;
