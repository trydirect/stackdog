import { mergeEnv, readEnv } from '../env';

describe('mergeEnv', () => {
  it('lets runtime values override what was compiled in', () => {
    const merged = mergeEnv(
      { REACT_APP_API_URL: 'http://localhost:5000/api', REACT_APP_API_PORT: '5000' },
      { REACT_APP_API_URL: 'http://192.0.2.10:5000/api' }
    );

    expect(merged.REACT_APP_API_URL).toBe('http://192.0.2.10:5000/api');
    expect(merged.REACT_APP_API_PORT).toBe('5000');
  });

  it('ignores empty runtime values, which is what an unset container env writes', () => {
    const merged = mergeEnv(
      { REACT_APP_API_URL: 'http://localhost:5000/api' },
      { REACT_APP_API_URL: '', REACT_APP_WS_URL: '' }
    );

    expect(merged.REACT_APP_API_URL).toBe('http://localhost:5000/api');
    expect(merged.REACT_APP_WS_URL).toBeUndefined();
  });
});

describe('readEnv', () => {
  const globalScope = globalThis as unknown as { __STACKDOG_ENV__?: unknown };

  afterEach(() => {
    delete globalScope.__STACKDOG_ENV__;
  });

  it('reads what config.js put on the global scope', () => {
    globalScope.__STACKDOG_ENV__ = { REACT_APP_API_URL: 'http://192.0.2.10:5000/api' };
    expect(readEnv().REACT_APP_API_URL).toBe('http://192.0.2.10:5000/api');
  });

  it('survives a missing config.js', () => {
    expect(() => readEnv()).not.toThrow();
  });
});
