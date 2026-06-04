import { NextResponse } from 'next/server';
import { z } from 'zod';

const topics = [
  'General Inquiry',
  'Enterprise',
  'Security Report',
  'Bug Report',
  'Feature Request',
  'Other'
] as const;

const contactSchema = z.object({
  name: z.string().trim().min(2).max(80),
  email: z.string().trim().email().max(120),
  company: z.string().trim().max(120).optional(),
  topic: z.enum(topics),
  message: z.string().trim().min(20).max(4000)
});

function escapeSlackText(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export async function POST(request: Request) {
  try {
    const webhookUrl = process.env.STACKER_PIPE_WEBHOOK_URL;

    if (!webhookUrl) {
      return NextResponse.json(
        { error: 'Contact form webhook is not configured.' },
        { status: 500 }
      );
    }

    const payload = contactSchema.parse(await request.json());

    const company = payload.company?.trim() ? payload.company.trim() : 'Not provided';
    const timestamp = new Date().toISOString();

    // Production note: add IP-based rate limiting and bot protection before exposing this route publicly.
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        text: '📧 New contact from Stackdog website',
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: '📧 New Contact Form Submission'
            }
          },
          {
            type: 'section',
            fields: [
              {
                type: 'mrkdwn',
                text: `*Name:*\n${escapeSlackText(payload.name)}`
              },
              {
                type: 'mrkdwn',
                text: `*Email:*\n${escapeSlackText(payload.email)}`
              },
              {
                type: 'mrkdwn',
                text: `*Company:*\n${escapeSlackText(company)}`
              },
              {
                type: 'mrkdwn',
                text: `*Topic:*\n${escapeSlackText(payload.topic)}`
              }
            ]
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Message:*\n${escapeSlackText(payload.message)}`
            }
          },
          {
            type: 'divider'
          },
          {
            type: 'context',
            elements: [
              {
                type: 'mrkdwn',
                text: `Submitted at ${timestamp} from stackdog.io`
              }
            ]
          }
        ]
      }),
      cache: 'no-store'
    });

    if (!response.ok) {
      return NextResponse.json(
        { error: 'Unable to forward your message right now.' },
        { status: 502 }
      );
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    if (error instanceof z.ZodError) {
      const issue = error.issues[0];
      return NextResponse.json(
        { error: issue?.message ?? 'Please check the submitted fields.' },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { error: 'Unexpected error while submitting the contact form.' },
      { status: 500 }
    );
  }
}
