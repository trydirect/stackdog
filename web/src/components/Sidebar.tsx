import React from 'react';
import logoUrl from '../assets/logo.png';
import './Sidebar.css';

const Sidebar: React.FC = () => {
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
      <nav className="sidebar-nav">
        <a href="#overview">Overview</a>
        <a href="#threats">Threat Map</a>
        <a href="#alerts">Alerts</a>
        <a href="#containers">Containers</a>
      </nav>
    </aside>
  );
};

export default Sidebar;
