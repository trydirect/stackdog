import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import Sidebar from '../Sidebar';

jest.mock('../../assets/logo.png', () => 'logo.png');

const originalResizeObserver = global.ResizeObserver;
const disconnect = jest.fn();
let resizeCallback: ResizeObserverCallback;
let sectionTops: Record<string, number>;

const Sections = () => (
  <main>
    <section id="overview" />
    <section id="threat-map"><div id="threats" /></section>
    <section id="alerts" />
    <section id="containers" />
  </main>
);

const activeLink = () => screen.getByRole('navigation', { name: 'Main navigation' })
  .querySelector('[aria-current="location"]');

describe('Sidebar navigation', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/');
    sectionTops = { overview: 32, 'threat-map': 600, alerts: 1800, containers: 3000 };
    Object.defineProperty(window, 'scrollY', { configurable: true, value: 0, writable: true });
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 800 });
    Object.defineProperty(document.documentElement, 'scrollHeight', { configurable: true, value: 4800 });
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: jest.fn().mockReturnValue({ matches: false }),
    });
    HTMLElement.prototype.scrollIntoView = jest.fn();
    jest.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
      return { top: sectionTops[this.id] ?? 0 } as DOMRect;
    });
    global.ResizeObserver = jest.fn().mockImplementation((callback) => {
      resizeCallback = callback;
      return { observe: jest.fn(), unobserve: jest.fn(), disconnect };
    });
    disconnect.mockClear();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(() => {
    global.ResizeObserver = originalResizeObserver;
  });

  test('tracks scrolling in both directions without replacing the URL fragment', () => {
    render(<><Sidebar /><Sections /></>);
    expect(activeLink()).toHaveTextContent('Overview');

    sectionTops = { overview: -1900, 'threat-map': -1300, alerts: -100, containers: 1100 };
    fireEvent.scroll(window);
    expect(activeLink()).toHaveTextContent('Alerts');
    expect(window.location.hash).toBe('');

    sectionTops = { overview: 32, 'threat-map': 600, alerts: 1800, containers: 3000 };
    fireEvent.scroll(window);
    expect(activeLink()).toHaveTextContent('Overview');
  });

  test('keeps a tall section active until the next section reaches the activation line', () => {
    sectionTops = { overview: -1800, 'threat-map': -1200, alerts: 650, containers: 1800 };
    render(<><Sidebar /><Sections /></>);
    expect(activeLink()).toHaveTextContent('Threat Map');

    sectionTops.alerts = 90;
    fireEvent.scroll(window);
    expect(activeLink()).toHaveTextContent('Alerts');
  });

  test('activates the last section at the bottom of the page', () => {
    sectionTops = { overview: -3900, 'threat-map': -3300, alerts: -2100, containers: 110 };
    window.scrollY = 4000;
    render(<><Sidebar /><Sections /></>);
    expect(activeLink()).toHaveTextContent('Containers');
  });

  test('smoothly navigates to the canonical section and activates its link', () => {
    render(<><Sidebar /><Sections /></>);
    fireEvent.click(screen.getByRole('link', { name: 'Threat Map' }));

    expect(document.getElementById('threat-map')!.scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'start' });
    expect(window.location.hash).toBe('#threat-map');
    expect(activeLink()).toHaveTextContent('Threat Map');
  });

  test('respects reduced motion when navigating', () => {
    (window.matchMedia as jest.Mock).mockReturnValue({ matches: true });
    render(<><Sidebar /><Sections /></>);
    fireEvent.click(screen.getByRole('link', { name: 'Containers' }));

    expect(document.getElementById('containers')!.scrollIntoView).toHaveBeenCalledWith({ behavior: 'auto', block: 'start' });
  });

  test('recognizes legacy threat links and alert detail fragments', () => {
    render(<><Sidebar /><Sections /></>);
    window.history.replaceState(null, '', '#threats');
    fireEvent(window, new Event('hashchange'));
    expect(activeLink()).toHaveTextContent('Threat Map');

    window.history.replaceState(null, '', '#alerts/alert-1');
    fireEvent(window, new Event('hashchange'));
    expect(activeLink()).toHaveTextContent('Alerts');
  });

  test('recalculates after asynchronous sections mount and disconnects on unmount', () => {
    const { rerender, unmount } = render(<><Sidebar /></>);
    sectionTops = { overview: -1900, 'threat-map': -1300, alerts: 24, containers: 1100 };
    rerender(<><Sidebar /><Sections /></>);
    act(() => resizeCallback([], {} as ResizeObserver));
    expect(activeLink()).toHaveTextContent('Alerts');

    unmount();
    expect(disconnect).toHaveBeenCalled();
  });

  test('collapses and expands while preserving accessible navigation and native titles', () => {
    render(<Sidebar />);
    const collapse = screen.getByRole('button', { name: 'Collapse sidebar' });
    expect(collapse).toHaveAttribute('aria-expanded', 'true');
    fireEvent.click(collapse);

    const expand = screen.getByRole('button', { name: 'Expand sidebar' });
    expect(expand).toHaveAttribute('aria-expanded', 'false');
    expect(screen.getByRole('link', { name: 'Threat Map' })).toHaveAttribute('title', 'Threat Map');
    expect(screen.getByRole('link', { name: 'Threat Map' })).toHaveAttribute('href', '#threat-map');
    fireEvent.click(expand);
    expect(screen.getByRole('button', { name: 'Collapse sidebar' })).toHaveAttribute('aria-expanded', 'true');
  });
});
