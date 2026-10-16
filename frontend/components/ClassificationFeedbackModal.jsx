'use client';

import React, { useState, useEffect } from 'react';
import {
  X,
  Flag,
  CheckCircle2,
  AlertTriangle,
  Paperclip,
  Shield,
  HelpCircle,
  Loader2,
  Send
} from 'lucide-react';
import { submitInvestigationFeedback } from '@/lib/api';

const FEEDBACK_CATEGORIES = [
  {
    id: 'FALSE_POSITIVE',
    label: 'False Positive',
    description: 'Legitimate business message or clean attachment was incorrectly flagged as a threat.'
  },
  {
    id: 'FALSE_NEGATIVE',
    label: 'False Negative',
    description: 'Malicious payload, phishing link, or evasion tactic was missed or rated too low.'
  },
  {
    id: 'INCORRECT_FILE_TYPE',
    label: 'Incorrect File Type',
    description: 'Detected binary format or MIME identification is wrong (e.g. valid document misidentified).'
  },
  {
    id: 'INCORRECT_RISK_LEVEL',
    label: 'Incorrect Risk Level',
    description: 'The assigned risk rating (Low/Medium/High) appears inconsistent with the recorded findings.'
  },
  {
    id: 'OTHER',
    label: 'Other Feedback',
    description: 'Linguistic parsing error, false urgency indicator, or general inspection feedback.'
  }
];

export default function ClassificationFeedbackModal({
  isOpen,
  onClose,
  investigationId,
  attachments = [],
  preselectedAttachment = null,
  onFeedbackSubmitted
}) {
  const [category, setCategory] = useState('FALSE_POSITIVE');
  const [selectedAttachment, setSelectedAttachment] = useState('');
  const [explanation, setExplanation] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successResult, setSuccessResult] = useState(null);

  useEffect(() => {
    if (isOpen) {
      setErrorMsg('');
      setSuccessResult(null);
      setExplanation('');
      if (preselectedAttachment) {
        setSelectedAttachment(preselectedAttachment);
        setCategory('INCORRECT_FILE_TYPE');
      } else {
        setSelectedAttachment('');
        setCategory('FALSE_POSITIVE');
      }
    }
  }, [isOpen, preselectedAttachment]);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setSubmitting(true);

    try {
      const payload = {
        category,
        attachment_filename: selectedAttachment || null,
        explanation: explanation.trim() || null
      };

      const result = await submitInvestigationFeedback(investigationId, payload);
      setSuccessResult(result);
      if (onFeedbackSubmitted) {
        onFeedbackSubmitted(result);
      }
      setTimeout(() => {
        // Auto-close after 2.5s on success
        setSuccessResult(null);
        onClose();
      }, 2500);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to submit feedback.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-fade-in">
      <div
        className="relative w-full max-w-lg rounded-xl border border-border bg-card shadow-2xl p-6 space-y-5 overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between border-b border-border/80 pb-4">
          <div className="space-y-1">
            <span className="eyebrow flex items-center gap-1.5 text-primary">
              <Flag className="w-3.5 h-3.5" />
              HUMAN-IN-THE-LOOP FEEDBACK
            </span>
            <h2 className="text-base font-semibold text-foreground">
              Report Classification Issue
            </h2>
            <p className="text-xs text-muted-foreground">
              Help calibrate PhishGuard AI&apos;s deterministic rules and reduce false-positive rates.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-secondary/60 transition cursor-pointer"
            title="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Success State */}
        {successResult ? (
          <div className="p-6 text-center space-y-3 bg-emerald-500/[0.05] border border-emerald-500/20 rounded-lg">
            <CheckCircle2 className="w-10 h-10 text-success mx-auto" />
            <h3 className="text-sm font-semibold text-foreground">
              Feedback Successfully Recorded
            </h3>
            <p className="text-xs text-muted-foreground leading-relaxed max-w-sm mx-auto">
              Your feedback (ID: <code className="font-mono text-primary font-bold">{successResult.id}</code>) has been persisted to MongoDB alongside the original prediction snapshot.
            </p>
            <span className="text-[10px] font-mono text-muted-foreground block">
              Status: {successResult.status} · Preserved for evaluation benchmark
            </span>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            {/* Error Message */}
            {errorMsg && (
              <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-700 text-xs flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{errorMsg}</span>
              </div>
            )}

            {/* 1. Category Selection */}
            <div className="space-y-1.5">
              <label className="font-mono text-[10px] font-bold uppercase text-foreground block">
                Feedback Category <span className="text-primary">*</span>
              </label>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {FEEDBACK_CATEGORIES.map((cat) => (
                  <label
                    key={cat.id}
                    className={`flex items-start gap-2.5 p-2.5 rounded border cursor-pointer transition ${
                      category === cat.id
                        ? 'bg-primary/5 border-primary text-foreground'
                        : 'bg-background border-border text-muted-foreground hover:bg-secondary/40'
                    }`}
                  >
                    <input
                      type="radio"
                      name="feedback_category"
                      value={cat.id}
                      checked={category === cat.id}
                      onChange={(e) => setCategory(e.target.value)}
                      className="mt-0.5 text-primary"
                    />
                    <div>
                      <strong className="font-semibold text-foreground block text-xs">
                        {cat.label}
                      </strong>
                      <span className="text-[11px] leading-tight block text-muted-foreground mt-0.5">
                        {cat.description}
                      </span>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* 2. Target Attachment Selector (if attachments exist) */}
            {attachments.length > 0 && (
              <div className="space-y-1.5">
                <label className="font-mono text-[10px] font-bold uppercase text-foreground block">
                  Relevant Attachment (Optional)
                </label>
                <div className="relative">
                  <select
                    value={selectedAttachment}
                    onChange={(e) => setSelectedAttachment(e.target.value)}
                    className="w-full h-8 px-2.5 text-xs font-mono rounded border border-border bg-background text-foreground focus:outline-none focus:border-primary"
                  >
                    <option value="">(General Email / Whole Investigation)</option>
                    {attachments.map((att, idx) => (
                      <option key={`${att.filename}-${idx}`} value={att.filename}>
                        📎 {att.filename} ({att.detected_type || 'Unknown'} · {att.risk_level || 'LOW'})
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            )}

            {/* 3. User Explanation / Comments */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="font-mono text-[10px] font-bold uppercase text-foreground">
                  Observations / Rationale (Optional)
                </label>
                <span className="text-[10px] font-mono text-muted-foreground">
                  {explanation.length}/2000
                </span>
              </div>
              <textarea
                value={explanation}
                onChange={(e) => setExplanation(e.target.value)}
                maxLength={2000}
                placeholder="Explain why this detection appears incorrect (e.g., 'Internal company payroll sheet with legitimate macros', 'Vendor invoice from approved SAP portal')..."
                className="w-full h-20 p-2.5 text-xs rounded border border-border bg-background text-foreground focus:outline-none focus:border-primary leading-relaxed resize-none"
              />
            </div>

            {/* Notice */}
            <div className="p-2.5 rounded bg-secondary/40 border border-border/60 text-[11px] text-muted-foreground leading-relaxed flex items-start gap-2">
              <Shield className="w-3.5 h-3.5 text-primary shrink-0 mt-0.5" />
              <span>
                <strong>Evaluation Transparency:</strong> User feedback logs user opinions and preserves original risk predictions without immediately altering authoritative security scores.
              </span>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-border/80">
              <button
                type="button"
                onClick={onClose}
                disabled={submitting}
                className="px-3 py-1.5 rounded text-xs font-medium border border-border bg-background text-muted-foreground hover:bg-secondary/60 transition cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded text-xs font-medium bg-primary text-primary-foreground hover:opacity-90 transition cursor-pointer disabled:opacity-50"
              >
                {submitting ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Submitting...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-3.5 h-3.5" />
                    <span>Submit Feedback</span>
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
