const DEFAULT_SITE_URL = 'https://stackdog.app';
const DEFAULT_GA_MEASUREMENT_ID = 'G-1ERSVH1L4D';

export function getSiteUrl(): string {
  return process.env.NEXT_PUBLIC_SITE_URL || process.env.SITE_URL || DEFAULT_SITE_URL;
}

/** Google Analytics measurement ID. Set to an empty string to disable the tag. */
export function getGaMeasurementId(): string {
  return process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID ?? DEFAULT_GA_MEASUREMENT_ID;
}
