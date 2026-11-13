export type PortEnvLike = {
  APP_PORT?: string;
  REACT_APP_API_PORT?: string;
};

export const DEFAULT_API_PORT = '5000';

export function resolveApiPort(env: PortEnvLike): string {
  return env.REACT_APP_API_PORT || env.APP_PORT || DEFAULT_API_PORT;
}
