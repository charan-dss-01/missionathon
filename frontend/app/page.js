'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  ChevronDown,
  Menu,
  X,
  FileCode,
  Lock,
  ArrowRight
} from 'lucide-react';
import LiquidShaderBackground from '@/components/LiquidShaderBackground';

export default function PhishGuardLandingPage() {
  const router = useRouter();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [openFaq, setOpenFaq] = useState(null);

  // Eagerly prefetch target routes immediately on landing mount
  useEffect(() => {
    router.prefetch('/investigate');
    router.prefetch('/overview');
  }, [router]);

  const toggleFaq = (idx) => {
    setOpenFaq(openFaq === idx ? null : idx);
  };

  const securityEngines = [
    {
      stage: 'STAGE 01',
      tag: 'Input Ingestion',
      title: 'Input Parser & RFC Validator',
      subtitle: 'Inbound Email Normalization',
      desc: 'Extracts RFC 5322 headers, MIME boundary structures, plain/HTML text, embedded URI tokens, and raw attachment byte payloads to establish an untampered forensic baseline.',
      input: '.eml files, raw email headers, plain/HTML body',
      output: 'PAR Evidence Record',
    },
    {
      stage: 'STAGE 02',
      tag: 'Identity Verification',
      title: 'Header & Protocol Analyzer',
      subtitle: 'Authentication & Anti-Spoofing',
      desc: 'Validates SPF, DKIM, and DMARC alignment headers, inspects Reply-To versus Return-Path mismatches, and flags display name spoofing attacks with authoritative Python rules.',
      input: 'Authentication-Results, Return-Path, DKIM-Signature',
      output: 'HDR Evidence Record',
    },
    {
      stage: 'STAGE 03',
      tag: 'Content Heuristics',
      title: 'Body & Urgency Analyzer',
      subtitle: 'Lure & Credential Harvesting Detection',
      desc: 'Identifies manufactured urgency triggers, fake security notifications, financial extortion patterns, and deceptive anchor text versus href destination mismatches.',
      input: 'Decoded text, HTML DOM, embedded URI tokens',
      output: 'BDY Evidence Record',
    },
    {
      stage: 'STAGE 04',
      tag: 'Syntactic Inspection',
      title: 'URL & Link Inspector',
      subtitle: 'Syntactic Deception Detection',
      desc: 'Performs static lexical analysis: punycode homoglyphs, IP literal hosts, excessive subdomains, and suspicious brand typosquats without clicking or contacting remote hosts.',
      input: 'Normalized hyperlinks, query parameters',
      output: 'URL Evidence Record',
    },
    {
      stage: 'STAGE 05',
      tag: 'Static Byte Forensics',
      title: 'Attachment & Quishing Engine',
      subtitle: 'Air-Gapped Payload & QR Triage',
      desc: 'Performs safe byte-level inspection: file magic signatures, RTLO unicode inversion (\\u202e), double extension tricks, VBA macros, and in-memory QR barcode analysis without sandbox execution.',
      input: 'Attachment byte stream, MIME headers, QR images',
      output: 'ATT Evidence Record',
    },
  ];

  const faqs = [
    {
      q: 'How does PhishGuard eliminate hallucinated claims in security verdicts?',
      a: 'Every detection is derived strictly from deterministic Python security rules. The automated evidence validator cross-checks all LLM explanations against authoritative rule IDs; any unsupported claim is rejected before analyst presentation.',
    },
    {
      q: 'Is suspicious content ever executed or fetched over the live network?',
      a: 'Never. PhishGuard operates with 100% air-gapped static analysis. Links are never clicked, remote resources are never fetched, and attachments are never executed or rendered.',
    },
    {
      q: 'How does the deterministic scoring engine compute risk?',
      a: 'Risk ratings are calculated using discrete component scoring (Email Risk vs. Attachment Risk) with correlated indicator damping to prevent false inflation while ensuring critical findings trigger High Risk.',
    },
    {
      q: 'What happens if external LLM providers experience rate limits or downtime?',
      a: 'PhishGuard features a 3-tier resilient fallback: Google Gemini 1.5/2.0 Flash is primary, Groq Llama 3.3 activates automatically on HTTP 429 rate limits, and pure Python deterministic rule templates ensure uninterrupted offline triage if external APIs are unavailable.',
    },
    {
      q: 'How does PhishGuard detect Quishing (QR code phishing)?',
      a: 'The in-memory QR analyzer inspects image attachments using file magic byte verification and safe pixel limits before decoding. Extracted target URLs are defanged and statically triaged without making live network requests.',
    },
  ];

  return (
    <div className="min-h-screen bg-[#f8fafc] text-[#0f172a] font-sans antialiased selection:bg-[#fecdd3] selection:text-[#80142b]">
      {/* 1. Header / Navigation */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-[#f8fafc]/85 backdrop-blur-md border-b border-[#e2e8f0]/80 transition-all">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2.5 font-bold tracking-tight text-lg text-[#0f172a] group">
            <span className="text-[#80142b] group-hover:text-[#6b1023] transition-colors font-mono font-semibold">\\</span>
            <span className="font-semibold text-[17px] tracking-[-0.02em]">PhishGuard<span className="text-[#64748b] font-normal">.ai</span></span>
          </Link>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-1 bg-[#f1f5f9]/90 p-1.5 rounded-full border border-[#e2e8f0] text-xs font-medium text-[#475569] shadow-xs">
            <a href="#how-it-works" className="px-3.5 py-1.5 rounded-full hover:text-[#0f172a] hover:bg-white transition-all">
              Architecture
            </a>
            <a href="#pipeline" className="px-3.5 py-1.5 rounded-full hover:text-[#0f172a] hover:bg-white transition-all">
              Security Engines
            </a>
            <a href="#faqs" className="px-3.5 py-1.5 rounded-full hover:text-[#0f172a] hover:bg-white transition-all">
              FAQs
            </a>
            <Link href="/overview" className="px-3.5 py-1.5 rounded-full hover:text-[#0f172a] hover:bg-white transition-all">
              Control Tower
            </Link>
          </nav>

          {/* Right Action Button - Deep Wine Matching Screenshot */}
          <div className="hidden md:flex items-center gap-3">
            <Link
              href="/investigate"
              prefetch={true}
              onMouseEnter={() => router.prefetch('/investigate')}
              onTouchStart={() => router.prefetch('/investigate')}
              className="inline-flex items-center justify-center bg-[#80142b] hover:bg-[#6b1023] text-white border border-[#6b1023] px-5 py-2.5 rounded-full text-xs font-semibold shadow-xs transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              New Investigation
            </Link>
          </div>

          {/* Mobile Hamburger Toggle */}
          <div className="flex md:hidden items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 text-[#475569] hover:text-[#0f172a] rounded-md"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden bg-[#f8fafc]/95 backdrop-blur-xl border-b border-[#e2e8f0] px-6 py-4 flex flex-col gap-3 shadow-lg">
            <a
              href="#how-it-works"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-[#475569] py-1.5"
            >
              Architecture
            </a>
            <a
              href="#pipeline"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-[#475569] py-1.5"
            >
              Security Engines
            </a>
            <a
              href="#faqs"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-[#475569] py-1.5"
            >
              FAQs
            </a>
            <Link
              href="/overview"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-[#475569] py-1.5"
            >
              Control Tower
            </Link>
            <Link
              href="/investigate"
              prefetch={true}
              onClick={() => setMobileMenuOpen(false)}
              onMouseEnter={() => router.prefetch('/investigate')}
              onTouchStart={() => router.prefetch('/investigate')}
              className="w-full text-center bg-[#80142b] hover:bg-[#6b1023] text-white border border-[#6b1023] py-2 rounded-full text-sm font-semibold mt-2"
            >
              New Investigation
            </Link>
          </div>
        )}
      </header>

      {/* 2. Hero Section with 3D Stippled Particle Liquid GLSL Animated Background */}
      <section className="relative min-h-[85vh] md:min-h-[92vh] flex items-center justify-center pt-24 pb-20 px-6 overflow-hidden bg-[#f8fafc]">
        {/* Three.js Stippled GLSL Liquid Canvas Background */}
        <LiquidShaderBackground className="absolute inset-0 z-0" />

        {/* Foreground Content */}
        <div className="relative z-10 max-w-4xl mx-auto text-center flex flex-col items-center">
          {/* Eyebrow Pill */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#fdf2f4] border border-[#fecdd3] shadow-[0_2px_8px_rgba(128,20,43,0.06)] text-[#80142b] text-xs font-semibold mb-7 backdrop-blur-sm animate-fade-in">
            <span className="text-[#80142b] text-xs">✦</span>
            <span>Tier-2 & Tier-3 SOC Cyber Defense</span>
          </div>

          {/* Main Title */}
          <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-[68px] font-bold text-[#0f172a] tracking-[-0.035em] leading-[1.12] mb-6 max-w-3xl">
            Investigate{' '}
            <span className="font-serif-italic font-normal text-[#80142b]">
              phishing threats
            </span>{' '}
            with multi-agent forensic precision.
          </h1>

          {/* Subtitle */}
          <p className="text-base sm:text-lg text-[#475569] max-w-2xl font-normal leading-relaxed mb-9">
            Autonomous, air-gapped static analysis of suspicious emails, RFC headers, hyperlinks, attachments, and QR codes — backed by deterministic security rules and LangGraph orchestration.
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row items-center gap-3.5 w-full sm:w-auto mb-10">
            <Link
              href="/investigate"
              prefetch={true}
              onMouseEnter={() => router.prefetch('/investigate')}
              onTouchStart={() => router.prefetch('/investigate')}
              className="w-full sm:w-auto inline-flex items-center justify-center bg-[#80142b] hover:bg-[#6b1023] text-white border border-[#6b1023] px-7 py-3 rounded-full text-sm font-semibold shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Start Live Investigation
            </Link>
            <Link
              href="/overview"
              prefetch={true}
              onMouseEnter={() => router.prefetch('/overview')}
              onTouchStart={() => router.prefetch('/overview')}
              className="w-full sm:w-auto inline-flex items-center justify-center bg-white hover:bg-[#f1f5f9] text-[#0f172a] border border-[#cbd5e1] px-7 py-3 rounded-full text-sm font-medium shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Control Tower Overview
            </Link>
          </div>

          {/* Sub-badge */}
          <div className="inline-flex items-center gap-2 text-xs font-medium text-[#64748b] tracking-wide">
            <span className="w-1.5 h-3 bg-[#80142b] rounded-[1px] inline-block" />
            <span>10 LangGraph Nodes • 100% Air-Gapped Static Analysis</span>
          </div>
        </div>
      </section>

      {/* 3. System Architecture Section */}
      <section id="how-it-works" className="py-24 px-6 max-w-7xl mx-auto border-t border-[#e2e8f0]">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-[#80142b] mb-3 block">
            SYSTEM ARCHITECTURE
          </span>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#0f172a] mb-4">
            Deterministic Rule Grounding & Multi-Tier AI Orchestration
          </h2>
          <p className="text-[#475569] text-sm sm:text-base leading-relaxed">
            Every incoming email sample undergoes rigorous static validation across 5 independent inspection engines.
            Authoritative verdicts are grounded in deterministic Python rules before LLM explanation synthesis.
          </p>
        </div>

        {/* Dynamic Architectural Grid with Crisp Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="p-8 rounded-2xl bg-white border border-[#e2e8f0] shadow-sm hover:shadow-md hover:border-[#cbd5e1] transition-all">
            <div className="w-10 h-10 rounded-xl bg-[#fdf2f4] border border-[#fecdd3] flex items-center justify-center text-[#80142b] mb-5 shadow-xs">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="text-lg font-semibold text-[#0f172a] mb-2">Air-Gapped Static Analysis</h3>
            <p className="text-sm text-[#475569] leading-relaxed">
              Zero outbound network execution. Suspicious URLs are never fetched, attachments are never executed, and external DNS is never probed during triage.
            </p>
          </div>

          <div className="p-8 rounded-2xl bg-white border border-[#e2e8f0] shadow-sm hover:shadow-md hover:border-[#cbd5e1] transition-all">
            <div className="w-10 h-10 rounded-xl bg-[#fdf2f4] border border-[#fecdd3] flex items-center justify-center text-[#80142b] mb-5 shadow-xs">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h3 className="text-lg font-semibold text-[#0f172a] mb-2">Deterministic Scoring Engine</h3>
            <p className="text-sm text-[#475569] leading-relaxed">
              Discrete component scoring separates Email Risk and Attachment Risk with correlated indicator damping to eliminate false score inflation.
            </p>
          </div>

          <div className="p-8 rounded-2xl bg-white border border-[#e2e8f0] shadow-sm hover:shadow-md hover:border-[#cbd5e1] transition-all">
            <div className="w-10 h-10 rounded-xl bg-[#fdf2f4] border border-[#fecdd3] flex items-center justify-center text-[#80142b] mb-5 shadow-xs">
              <FileCode className="w-5 h-5" />
            </div>
            <h3 className="text-lg font-semibold text-[#0f172a] mb-2">Strict Anti-Hallucination Gate</h3>
            <p className="text-sm text-[#475569] leading-relaxed">
              An automated evidence validator verifies all LLM claims against authoritative detection rule IDs; unsupported or hallucinated claims are discarded.
            </p>
          </div>
        </div>
      </section>

      {/* 4. Five Core Security Engines Section with Slate & Wine Theme */}
      <section id="pipeline" className="py-24 px-6 bg-[#f1f5f9]/60 border-t border-[#e2e8f0]">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-[#80142b] mb-3 block">
              DETECTION INFRASTRUCTURE
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#0f172a] mb-4">
              Five Autonomous Security Engines
            </h2>
            <p className="text-[#475569] text-sm sm:text-base leading-relaxed">
              Each specialized engine executes authoritative heuristic checks and compiles structured forensic records.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {securityEngines.map((eng, idx) => (
              <div
                key={idx}
                className="bg-white rounded-2xl p-7 border border-[#e2e8f0] shadow-sm hover:border-[#cbd5e1] hover:shadow-md transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-[10px] font-mono font-semibold px-2.5 py-1 rounded-md bg-[#f1f5f9] text-[#475569] border border-[#e2e8f0]">
                      {eng.stage}
                    </span>
                    <span className="text-[11px] font-medium text-[#80142b]">
                      {eng.tag}
                    </span>
                  </div>
                  <h3 className="text-base font-semibold text-[#0f172a] mb-1">
                    {eng.title}
                  </h3>
                  <div className="text-xs font-medium text-[#64748b] mb-3">
                    {eng.subtitle}
                  </div>
                  <p className="text-xs text-[#475569] leading-relaxed mb-6">
                    {eng.desc}
                  </p>
                </div>

                <div className="border-t border-[#f1f5f9] pt-4 space-y-1.5 text-[11px] font-mono text-[#64748b]">
                  <div className="flex justify-between">
                    <span className="text-[#94a3b8]">IN:</span>
                    <span className="text-[#334155] text-right truncate max-w-[200px]" title={eng.input}>{eng.input}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#94a3b8]">OUT:</span>
                    <span className="text-[#0f172a] font-semibold">{eng.output}</span>
                  </div>
                </div>
              </div>
            ))}

            {/* Sixth Callout Card - Deep Wine Matching Primary Screenshot Button */}
            <div className="bg-[#80142b] border border-[#6b1023] rounded-2xl p-7 text-white flex flex-col justify-between shadow-sm hover:shadow-md transition-all">
              <div>
                <span className="text-[10px] font-mono font-semibold px-2.5 py-1 rounded-md bg-[#6b1023] text-[#fecdd3] border border-[#9f1239] mb-4 inline-block">
                  ORCHESTRATION
                </span>
                <h3 className="text-lg font-bold text-white mb-2">LangGraph Multi-Agent Runtime</h3>
                <p className="text-xs text-[#fecdd3] leading-relaxed font-medium">
                  Coordinates Gemini 1.5 Flash and Groq Llama 3 with automatic state replay, deterministic fallbacks, and multi-tenant audit persistence in MongoDB Atlas.
                </p>
              </div>

              <Link
                href="/investigate"
                prefetch={true}
                onMouseEnter={() => router.prefetch('/investigate')}
                onTouchStart={() => router.prefetch('/investigate')}
                className="mt-6 inline-flex items-center justify-between bg-white text-[#80142b] border border-white px-4 py-2.5 rounded-lg text-xs font-semibold hover:bg-[#fdf2f4] transition-all"
              >
                <span>Start Live Investigation</span>
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* 5. Frequently Asked Questions */}
      <section id="faqs" className="py-24 px-6 max-w-4xl mx-auto border-t border-[#e2e8f0]">
        <div className="text-center mb-16">
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-[#80142b] mb-3 block">
            ARCHITECTURE & COMPLIANCE
          </span>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#0f172a]">
            Frequently Answered Questions
          </h2>
        </div>

        <div className="space-y-4">
          {faqs.map((faq, idx) => (
            <div
              key={idx}
              className="border border-[#e2e8f0] rounded-xl overflow-hidden bg-white shadow-2xs"
            >
              <button
                onClick={() => toggleFaq(idx)}
                className="w-full flex items-center justify-between p-5 text-left text-sm font-semibold text-[#0f172a] hover:bg-[#f8fafc] transition-colors"
              >
                <span>{faq.q}</span>
                <ChevronDown
                  className={`w-4 h-4 text-[#64748b] transition-transform duration-200 ${
                    openFaq === idx ? 'rotate-180 text-[#80142b]' : ''
                  }`}
                />
              </button>

              {openFaq === idx && (
                <div className="p-5 pt-0 text-xs sm:text-sm text-[#475569] leading-relaxed border-t border-[#f1f5f9] bg-[#f8fafc]/80">
                  {faq.a}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* 6. Ready to Triage CTA with Control Tower Palette */}
      <section className="py-20 px-6 bg-[#f8fafc] border-t border-[#e2e8f0] text-center">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-3xl font-bold tracking-tight text-[#0f172a] mb-4">
            Ready to investigate suspicious emails and threats?
          </h2>
          <p className="text-[#475569] text-sm sm:text-base max-w-xl mx-auto leading-relaxed mb-8">
            Launch the interactive Investigation console to analyze raw .eml files, inspect static rule detections, examine the Victim vs. Truth comparison, and view the execution trace.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3.5">
            <Link
              href="/investigate"
              prefetch={true}
              onMouseEnter={() => router.prefetch('/investigate')}
              onTouchStart={() => router.prefetch('/investigate')}
              className="w-full sm:w-auto inline-flex items-center justify-center bg-[#80142b] hover:bg-[#6b1023] text-white border border-[#6b1023] px-7 py-3 rounded-full text-sm font-semibold shadow-xs transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Open Investigation Console
            </Link>
            <Link
              href="/overview"
              prefetch={true}
              onMouseEnter={() => router.prefetch('/overview')}
              onTouchStart={() => router.prefetch('/overview')}
              className="w-full sm:w-auto inline-flex items-center justify-center bg-white hover:bg-[#f1f5f9] text-[#0f172a] border border-[#cbd5e1] px-7 py-3 rounded-full text-sm font-medium shadow-xs transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Control Tower Overview
            </Link>
          </div>
        </div>
      </section>

      {/* 7. Footer with Control Tower Palette */}
      <footer className="border-t border-[#e2e8f0] py-10 px-6 bg-[#f1f5f9]/70 text-xs text-[#64748b]">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-[#0f172a]">PhishGuard AI — Tier-2 & Tier-3 SOC Platform</span>
          </div>

          <div className="font-mono text-[#94a3b8] hidden md:block">
            Ingest &rarr; RFC Headers | Body &rarr; URLs | Attachments &amp; QR &rarr; Deterministic Evidence
          </div>

          <div className="flex items-center gap-4 text-[#64748b]">
            <span>Air-Gapped Static Analysis</span>
            <span>&bull;</span>
            <span>LangGraph Multi-Agent Orchestration</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
