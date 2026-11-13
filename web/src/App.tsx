import React from 'react';
import Dashboard from './components/Dashboard';
import Sidebar from './components/Sidebar';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';

const App: React.FC = () => {
  return (
    <div className="App app-layout">
      <Sidebar />
      <Dashboard />
    </div>
  );
};

export default App;
