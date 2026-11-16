"use client";

import { LoaderCircle, Send } from 'lucide-react';
import { ChangeEvent, FormEvent, useState } from 'react';

interface ContactFormProps {}

interface ContactFormValues {
  name: string;
  email: string;
  company: string;
  topic: ContactTopic;
  message: string;
}

type ContactTopic =
  | 'General Inquiry'
  | 'Enterprise'
  | 'Security Report'
  | 'Bug Report'
  | 'Feature Request'
  | 'Other';

const topicOptions: ContactTopic[] = [
  'General Inquiry',
  'Enterprise',
  'Security Report',
  'Bug Report',
  'Feature Request',
  'Other'
];

const initialValues: ContactFormValues = {
  name: '',
  email: '',
  company: '',
  topic: 'General Inquiry',
  message: ''
};

const fieldClassName =
  'w-full rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20';

export default function ContactForm(_: ContactFormProps) {
  const [values, setValues] = useState<ContactFormValues>(initialValues);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  const handleChange = (
    event: ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = event.target;
    const field = name as keyof ContactFormValues;
    setValues((current) => ({ ...current, [field]: value }));
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsSubmitting(true);
    setSuccessMessage('');
    setErrorMessage('');

    try {
      const response = await fetch('/api/contact', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(values)
      });

      const payload = (await response.json().catch(() => ({}))) as {
        error?: string;
        success?: boolean;
      };

      if (!response.ok || !payload.success) {
        throw new Error(payload.error ?? 'Unable to send your message right now.');
      }

      setSuccessMessage('Thanks — your message is on its way. We will get back to you shortly.');
      setValues(initialValues);
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Something went wrong while sending your message.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form className="panel p-6 sm:p-8" onSubmit={handleSubmit} noValidate>
      <div className="grid gap-5 sm:grid-cols-2">
        <div className="sm:col-span-1">
          <label htmlFor="name" className="mb-2 block text-sm font-medium text-slate-200">
            Name
          </label>
          <input
            id="name"
            name="name"
            type="text"
            value={values.name}
            onChange={handleChange}
            className={fieldClassName}
            placeholder="Jane Doe"
            autoComplete="name"
            required
            minLength={2}
            maxLength={80}
          />
        </div>

        <div className="sm:col-span-1">
          <label htmlFor="email" className="mb-2 block text-sm font-medium text-slate-200">
            Work email
          </label>
          <input
            id="email"
            name="email"
            type="email"
            value={values.email}
            onChange={handleChange}
            className={fieldClassName}
            placeholder="you@company.com"
            autoComplete="email"
            required
            maxLength={120}
          />
        </div>

        <div className="sm:col-span-1">
          <label htmlFor="company" className="mb-2 block text-sm font-medium text-slate-200">
            Company
          </label>
          <input
            id="company"
            name="company"
            type="text"
            value={values.company}
            onChange={handleChange}
            className={fieldClassName}
            placeholder="Optional"
            autoComplete="organization"
            maxLength={120}
          />
        </div>

        <div className="sm:col-span-1">
          <label htmlFor="topic" className="mb-2 block text-sm font-medium text-slate-200">
            Topic
          </label>
          <select
            id="topic"
            name="topic"
            value={values.topic}
            onChange={handleChange}
            className={fieldClassName}
            required
          >
            {topicOptions.map((topic) => (
              <option key={topic} value={topic}>
                {topic}
              </option>
            ))}
          </select>
        </div>

        <div className="sm:col-span-2">
          <label htmlFor="message" className="mb-2 block text-sm font-medium text-slate-200">
            Message
          </label>
          <textarea
            id="message"
            name="message"
            value={values.message}
            onChange={handleChange}
            className={`${fieldClassName} min-h-40 resize-y`}
            placeholder="Tell us about your environment, goals, or the issue you are investigating."
            required
            minLength={20}
            maxLength={4000}
          />
        </div>
      </div>

      <div className="mt-5 space-y-4" aria-live="polite">
        {successMessage ? (
          <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
            {successMessage}
          </div>
        ) : null}

        {errorMessage ? (
          <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            {errorMessage}
          </div>
        ) : null}
      </div>

      <div className="mt-6 flex flex-wrap items-center justify-between gap-4">
        <p className="max-w-xl text-sm text-slate-400">
          Use this form for demos, enterprise questions, disclosures, and roadmap conversations.
        </p>
        <button
          type="submit"
          disabled={isSubmitting}
          className="inline-flex items-center gap-2 rounded-full bg-cyan-500 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-70"
        >
          {isSubmitting ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
          {isSubmitting ? 'Sending...' : 'Send message'}
        </button>
      </div>
    </form>
  );
}
