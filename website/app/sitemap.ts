import type { MetadataRoute } from 'next';
import { getSiteUrl } from '@/lib/config';

export default function sitemap(): MetadataRoute.Sitemap {
  const siteUrl = getSiteUrl();
  const lastModified = new Date();

  return [
    {
      url: siteUrl,
      lastModified,
      changeFrequency: 'weekly',
      priority: 1
    },
    {
      url: `${siteUrl}/docs`,
      lastModified,
      changeFrequency: 'weekly',
      priority: 0.9
    },
    {
      url: `${siteUrl}/contact`,
      lastModified,
      changeFrequency: 'monthly',
      priority: 0.7
    }
  ];
}
