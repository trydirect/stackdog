import { DEFAULT_API_PORT, resolveApiPort } from '../ports';

describe('port configuration', () => {
  test('uses the backend default port when no frontend override is set', () => {
    expect(DEFAULT_API_PORT).toBe('5000');
    expect(resolveApiPort({})).toBe('5000');
  });

  test('prefers explicit frontend port overrides', () => {
    expect(resolveApiPort({ REACT_APP_API_PORT: '7000', APP_PORT: '5000' })).toBe('7000');
  });

  test('falls back to APP_PORT when frontend override is absent', () => {
    expect(resolveApiPort({ APP_PORT: '6000' })).toBe('6000');
  });
});
