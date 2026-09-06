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
        softwareVersion: '0.2.4',
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
          'AI tool use: the analyzer can check IPs, inspect containers, and ban attackers mid-investigation',
          'Threat scoring with 25+ built-in detectors',
          'ML behavioral drift detection with Isolation Forest',
          'File integrity monitoring, configuration audits, and Docker posture checks',
          'Automated nftables or iptables response with automatic unban',
          'Container quarantine and outbound spam containment',
          'Slack, email, and webhook alerts with severity filtering and deduplication'
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
