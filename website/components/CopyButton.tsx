"use client";

import { Check, Copy } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

interface CopyButtonProps {
  text: string;
  label?: string;
}

export default function CopyButton({ text, label = 'Copy command' }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      timeoutRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-3 py-2 text-sm font-medium text-slate-200 transition-colors hover:border-cyan-400/60 hover:text-white"
      aria-label={label}
    >
      {copied ? <Check className="h-4 w-4 text-emerald-300" /> : <Copy className="h-4 w-4" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}
