import { getSiteUrl } from '@/lib/config';

export interface FaqEntry {
  question: string;
  answer: string;
}

interface TechArticleInput {
  title: string;
  description: string;
  url: string;
}

const SITE_URL = getSiteUrl();
const GITHUB_URL = 'https://github.com/trydirect/stackdog';

export function buildHomeStructuredData(faqEntries: FaqEntry[]) {
  return {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'SoftwareApplication',
        name: 'Stackdog Security',
        applicationCategory: 'SecurityApplication',
        operatingSystem: 'Linux',
        softwareVersion: '0.2.2',
        url: SITE_URL,
        downloadUrl: GITHUB_URL,
        description:
          'Rust-native security platform for Docker containers and Linux servers with eBPF monitoring, AI log analysis, anomaly detection, and automated firewall response.',
        creator: {
          '@type': 'Person',
          name: 'Vasili Pascal'
        },
        publisher: {
          '@type': 'Organization',
          name: 'try.direct',
          email: 'info@try.direct'
        },
        featureList: [
          'eBPF-based syscall monitoring with <5% CPU overhead',
          'AI-assisted log sniffing via OpenAI, Ollama, and Candle workflows',
          'Threat scoring with 10+ built-in signatures',
          'Automated nftables or iptables response',
          'Container quarantine',
          'Slack, email, and webhook alerts'
        ],
        offers: {
          '@type': 'Offer',
          price: '0',
          priceCurrency: 'USD'
        },
        sameAs: [GITHUB_URL, 'https://twitter.com/VasiliiPascal']
      },
      {
        '@type': 'FAQPage',
        mainEntity: faqEntries.map((entry) => ({
          '@type': 'Question',
          name: entry.question,
          acceptedAnswer: {
            '@type': 'Answer',
            text: entry.answer
          }
        }))
      }
    ]
  };
}

export function buildDocsStructuredData({ title, description, url }: TechArticleInput) {
  return {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: title,
    description,
    url,
    author: {
      '@type': 'Person',
      name: 'Vasili Pascal'
    },
    publisher: {
      '@type': 'Organization',
      name: 'try.direct'
    },
    about: ['Stackdog CLI', 'Container security', 'eBPF monitoring', 'Threat detection'],
    articleSection: ['Getting Started', 'CLI Reference', 'REST API', 'Configuration'],
    proficiencyLevel: 'Intermediate'
  };
}

export function toJsonLd(value: unknown): string {
  return JSON.stringify(value);
}
