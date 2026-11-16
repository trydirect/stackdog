export type StackdogEnv = {
  REACT_APP_API_URL?: string;
  REACT_APP_WS_URL?: string;
  APP_PORT?: string;
  REACT_APP_API_PORT?: string;
};

declare const __STACKDOG_ENV__: StackdogEnv;

declare global {
  // Written by /config.js, which the published image generates at container
  // start from its environment.
  interface Window {
    __STACKDOG_ENV__?: StackdogEnv;
  }
}

/**
 * Settings for reaching the API, runtime first.
 *
 * The published dashboard image is generic: one image serves every
 * installation, so the API address cannot be baked into the bundle. The
 * container writes /config.js at start, and those values win over anything
 * compiled in. The build-time constant remains the fallback for `npm start`
 * and for images built with build args.
 */
export function readEnv(): StackdogEnv {
  const buildTime: StackdogEnv = typeof __STACKDOG_ENV__ === 'undefined' ? {} : __STACKDOG_ENV__;
  const runtime =
    (globalThis as unknown as { __STACKDOG_ENV__?: StackdogEnv }).__STACKDOG_ENV__ ?? {};

  return mergeEnv(buildTime, runtime);
}

/** Runtime values win, but only when they are actually set. */
export function mergeEnv(buildTime: StackdogEnv, runtime: StackdogEnv): StackdogEnv {
  const merged: StackdogEnv = { ...buildTime };

  (Object.keys(runtime) as (keyof StackdogEnv)[]).forEach(key => {
    const value = runtime[key];
    if (value !== undefined && value !== null && value !== '') {
      merged[key] = value;
    }
  });

  return merged;
}

/** Use the dashboard host when no explicit API endpoint was configured. */
export function defaultApiUrl(port: string): string {
  const protocol = typeof window !== 'undefined' && window.location.protocol === 'https:'
    ? 'https:'
    : 'http:';
  const hostname = typeof window !== 'undefined' && window.location.hostname
    ? window.location.hostname
    : 'localhost';

  return `${protocol}//${hostname}:${port}/api`;
}

export function defaultWebSocketUrl(port: string): string {
  const protocol = typeof window !== 'undefined' && window.location.protocol === 'https:'
    ? 'wss:'
    : 'ws:';
  const hostname = typeof window !== 'undefined' && window.location.hostname
    ? window.location.hostname
    : 'localhost';

  return `${protocol}//${hostname}:${port}/ws`;
}
