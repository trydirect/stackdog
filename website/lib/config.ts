const DEFAULT_SITE_URL = 'https://stackdog.stacker.my';

export function getSiteUrl(): string {
  return process.env.NEXT_PUBLIC_SITE_URL || process.env.SITE_URL || DEFAULT_SITE_URL;
}
