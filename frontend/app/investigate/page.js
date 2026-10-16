'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  ShieldAlert,
  Upload,
  Link as LinkIcon,
  FileCode,
  Sparkles,
  ArrowRight,
  AlertTriangle,
  Play,
  RotateCcw,
  Zap,
  Info,
  Shield,
  Layers,
  Cpu,
  CheckCircle2,
  Lock
} from 'lucide-react';
import { analyzeFormData } from '@/lib/api';

const PRESETS = [
  {
    name: 'Phishing: M365 Credential Theft',
    type: 'raw_text',
    desc: 'High urgency, deceptive anchor link, Reply-To diversion, SPF failure.',
    content: `From: "Microsoft Security Team" <security-alert@company-notice.com>
Reply-To: exfiltrate@drop-box-mail.ru
To: victim@enterprise-corp.com
Subject: ACTION REQUIRED: Your Microsoft 365 Password Expires in 24 Hours!
Date: Mon, 16 Oct 2026 10:14:00 +0000
Authentication-Results: spf=fail dkim=none dmarc=fail

Dear Employee,

Your Microsoft 365 work account password will expire within 24 hours. Failure to comply will result in immediate account suspension and revocation of all corporate credentials.

Please confirm your password and submit your one-time verification code immediately to keep your access active:
<a href="http://login-m365-verify.attacker-portal.net/auth">https://account.microsoft.com/security</a>

Sincerely,
Corporate IT Helpdesk & Security Operations`
  },
  {
    name: 'Benign: Monthly Cloud Invoice',
    type: 'raw_text',
    desc: 'Authentic correspondence, SPF/DKIM/DMARC pass, legitimate URL.',
    content: `From: "CloudProvider Billing" <billing@cloudprovider.com>
To: accounts@enterprise-corp.com
Subject: Monthly Cloud Infrastructure Invoice - October 2026
Date: Mon, 16 Oct 2026 08:30:00 +0000
Authentication-Results: spf=pass dkim=pass dmarc=pass header.from=cloudprovider.com

Hello Accounts Team,

Your monthly invoice for cloud infrastructure compute and storage services is now available for review.

Invoice Number: INV-2026-10-8821
Amount Due: $1,248.50
Due Date: November 15, 2026

You can review your breakdown and download the statement here:
https://cloudprovider.com/invoices/2026-10

Thank you for your business.
CloudProvider Customer Care`
  },
  {
    name: 'Phishing: Urgent CEO Wire Transfer',
    type: 'raw_text',
    desc: 'Executive display-name spoofing, coercive financial demand.',
    content: `From: "Jane Doe (Chief Executive Officer)" <executive-private-cell@mail-fast-temp.com>
Reply-To: jane.ceo.direct@gmail-priority.com
To: finance-director@enterprise-corp.com
Subject: Quick favor - Urgent wire transfer for acquisition
Date: Mon, 16 Oct 2026 11:00:00 +0000

Hi,

I am currently tied up in an all-day executive board meeting and cannot take calls. 
We have finalized the NDA on the acquisition project and require an urgent wire transfer payment of $48,500 to our external legal counsel today.

Please remit payment immediately using the updated bank account details attached below. 
Do not discuss this with anyone in the office as the deal is strictly confidential under SEC rules.

Jane Doe
Chief Executive Officer`
  }
];

export default function InvestigatePage() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState('raw_text');
  const [rawContent, setRawContent] = useState(PRESETS[0].content);
  const [urlInput, setUrlInput] = useState('');
  const [uploadedFile, setUploadedFile] = useState(null);

  // Fallback Testing Switches
  const [forceFallback, setForceFallback] = useState(false);
  const [simulateBothFail, setSimulateBothFail] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [loadingStep, setLoadingStep] = useState('');

  const handlePresetSelect = (preset) => {
    setActiveTab(preset.type);
    setRawContent(preset.content);
    setUploadedFile(null);
    setError(null);
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setUploadedFile(file);
      setError(null);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setLoadingStep('Initializing 10-node LangGraph orchestration...');

    try {
      const formData = new FormData();
      formData.append('force_fallback', forceFallback ? 'true' : 'false');
      formData.append('simulate_both_fail', simulateBothFail ? 'true' : 'false');

      if (activeTab === 'eml' || activeTab === 'attachment') {
        if (!uploadedFile) {
          throw new Error('Please select a file to upload.');
        }
        formData.append('file', uploadedFile);
        formData.append('input_type', activeTab);
      } else if (activeTab === 'url') {
        if (!urlInput.trim()) {
          throw new Error('Please enter a target URL to inspect.');
        }
        formData.append('raw_content', urlInput.trim());
        formData.append('input_type', 'url');
      } else {
        if (!rawContent.trim()) {
          throw new Error('Please paste email headers and body to analyze.');
        }
        formData.append('raw_content', rawContent.trim());
        formData.append('input_type', 'raw_text');
      }

      setLoadingStep('Executing deterministic Python rules & AI synthesis...');
      const result = await analyzeFormData(formData);

      setLoadingStep('Compilation complete. Redirecting to investigation dossier...');
      router.push(`/investigations/${result.id}`);
    } catch (err) {
      console.error(err);
      setError(err.message || 'An error occurred during investigation execution.');
      setLoading(false);
    }
  };

  return (
    <div className="overview-layout space-y-6">
      {/* 1. Page Heading */}
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-line" />
            STATIC SECURITY GATEWAY
          </span>
          <h1>
            New Investigation<span className="heading-dot">.</span>
          </h1>
          <p>
            Air-gapped static inspection of suspicious email content, RFC 5322 MIME messages, URLs, and file attachments.
          </p>
        </div>
        <div className="page-heading-actions">
          <span className="static-snapshot text-xs">
            <span className="health-dot tone-info" />
            Zero external navigation
          </span>
        </div>
      </div>

      {/* 2. Synthetic Test Fixtures */}
      <div className="bg-card border border-border rounded-md p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-warning" />
            <span className="text-xs font-semibold uppercase tracking-wider text-foreground">
              Synthetic Test Fixtures
            </span>
          </div>
          <span className="text-[10px] font-mono text-muted-foreground">
            1-Click Benchmark Datasets
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {PRESETS.map((preset, idx) => (
            <button
              key={preset.name}
              type="button"
              onClick={() => handlePresetSelect(preset)}
              className="p-3 rounded border border-border bg-background hover:bg-accent text-left space-y-1 transition cursor-pointer"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-foreground">
                  {preset.name.split(':')[0]}
                </span>
                <span className="text-[9px] font-mono text-muted-foreground">
                  Fixture 0{idx + 1}
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground leading-tight">
                {preset.name.split(':')[1]}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* 3. Main Intake Form */}
      <form onSubmit={handleSubmit} className="bg-card border border-border rounded-md p-6 space-y-5">
        {/* Tab Controls */}
        <div className="table-tabs border-b border-border pb-3">
          <button
            type="button"
            onClick={() => setActiveTab('raw_text')}
            className={`table-tab ${activeTab === 'raw_text' ? 'active' : ''}`}
          >
            <FileCode className="w-3.5 h-3.5 inline mr-1" />
            Raw Text / Email
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('eml')}
            className={`table-tab ${activeTab === 'eml' ? 'active' : ''}`}
          >
            <Upload className="w-3.5 h-3.5 inline mr-1" />
            .EML File Upload
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('url')}
            className={`table-tab ${activeTab === 'url' ? 'active' : ''}`}
          >
            <LinkIcon className="w-3.5 h-3.5 inline mr-1" />
            URL Inspection
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('attachment')}
            className={`table-tab ${activeTab === 'attachment' ? 'active' : ''}`}
          >
            <ShieldAlert className="w-3.5 h-3.5 inline mr-1" />
            Attachment Byte Scan
          </button>
        </div>

        {error && (
          <div className="error-box p-3 rounded border border-danger/30 bg-danger/10 text-danger text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Tab Content: Raw Text */}
        {activeTab === 'raw_text' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <label className="text-foreground font-medium">
                RFC 5322 Headers & Plain / HTML Body
              </label>
              <span className="text-[11px] font-mono text-muted-foreground">
                {rawContent.length} characters
              </span>
            </div>
            <textarea
              rows={12}
              value={rawContent}
              onChange={(e) => setRawContent(e.target.value)}
              placeholder="Paste headers (From, To, Subject, Authentication-Results) and message body..."
              className="w-full bg-background border border-input rounded p-3 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
        )}

        {/* Tab Content: .EML Upload */}
        {activeTab === 'eml' && (
          <div className="space-y-2">
            <label className="text-xs text-foreground font-medium block">
              Upload Standard RFC 5322 .EML Message (Max 10 MB)
            </label>
            <div className="border border-dashed border-border rounded p-8 text-center bg-background hover:bg-accent/40 transition">
              <Upload className="w-8 h-8 text-primary mx-auto mb-2" />
              <input
                type="file"
                accept=".eml"
                onChange={handleFileChange}
                className="hidden"
                id="eml-upload"
              />
              <label
                htmlFor="eml-upload"
                className="cursor-pointer text-xs font-semibold text-primary hover:underline block"
              >
                {uploadedFile ? uploadedFile.name : 'Browse computer for .eml file'}
              </label>
              <p className="text-[11px] text-muted-foreground mt-1">
                {uploadedFile
                  ? `${(uploadedFile.size / 1024).toFixed(1)} KB selected`
                  : 'Multipart email messages with embedded MIME headers and attachments'}
              </p>
            </div>
          </div>
        )}

        {/* Tab Content: URL Scan */}
        {activeTab === 'url' && (
          <div className="space-y-2">
            <label className="text-xs text-foreground font-medium block">
              Target URL for Syntactic Structural Analysis
            </label>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://login.microsoftonline.com.attacker-spoof.net/auth"
              className="w-full bg-background border border-input rounded p-2.5 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <p className="text-[11px] text-muted-foreground">
              Analyzes IP literals, punycode homoglyphs, deceptive subdomains, and obfuscations. Zero outbound HTTP requests.
            </p>
          </div>
        )}

        {/* Tab Content: Attachment Scan */}
        {activeTab === 'attachment' && (
          <div className="space-y-2">
            <label className="text-xs text-foreground font-medium block">
              Direct File Attachment Inspection (Max 5 MB)
            </label>
            <div className="border border-dashed border-border rounded p-8 text-center bg-background hover:bg-accent/40 transition">
              <ShieldAlert className="w-8 h-8 text-warning mx-auto mb-2" />
              <input
                type="file"
                onChange={handleFileChange}
                className="hidden"
                id="attachment-upload"
              />
              <label
                htmlFor="attachment-upload"
                className="cursor-pointer text-xs font-semibold text-primary hover:underline block"
              >
                {uploadedFile ? uploadedFile.name : 'Browse computer for suspicious attachment'}
              </label>
              <p className="text-[11px] text-muted-foreground mt-1">
                {uploadedFile
                  ? `${(uploadedFile.size / 1024).toFixed(1)} KB selected`
                  : 'Magic byte signature matching, RTLO detection, double extensions, and macro inspection'}
              </p>
            </div>
          </div>
        )}

        {/* Fallback Simulation Toggles */}
        <div className="pt-3 border-t border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 cursor-pointer text-muted-foreground hover:text-foreground">
              <input
                type="checkbox"
                checked={forceFallback}
                onChange={(e) => setForceFallback(e.target.checked)}
                className="rounded border-input text-primary focus:ring-primary"
              />
              <span>Simulate Gemini 429 ➔ Failover to Groq</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer text-muted-foreground hover:text-foreground">
              <input
                type="checkbox"
                checked={simulateBothFail}
                onChange={(e) => setSimulateBothFail(e.target.checked)}
                className="rounded border-input text-primary focus:ring-primary"
              />
              <span>Simulate Offline Rule Gating</span>
            </label>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 whitespace-nowrap font-medium cursor-pointer bg-primary text-primary-foreground shadow-sm hover:opacity-90 h-9 rounded-md px-5 text-xs disabled:opacity-50"
          >
            {loading ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                <span>{loadingStep || 'Executing LangGraph Pipeline...'}</span>
              </>
            ) : (
              <>
                <span>Run Investigation</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </div>
      </form>

      {/* 4. Privacy & Air-Gap Disclaimer Notice */}
      <div className="review-notice p-4 rounded border border-border bg-card text-xs space-y-1.5">
        <strong className="text-foreground flex items-center gap-1.5 font-semibold">
          <Lock className="w-3.5 h-3.5 text-primary" />
          Air-Gapped Privacy & Safety Guarantees
        </strong>
        <p className="text-muted-foreground leading-relaxed text-[11px]">
          PhishGuard AI executes deterministic Python security rules locally before optional LLM synthesis. Links are never clicked, remote resources are never loaded, and attachments are inspected via safe byte offsets. PII (credit cards, tokens, SSNs) is automatically redacted before any external model interaction.
        </p>
      </div>
    </div>
  );
}
