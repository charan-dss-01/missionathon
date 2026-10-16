'use client';

import React, { useState } from 'react';
import Link from 'next/link';
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
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [openFaq, setOpenFaq] = useState(null);

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
      desc: 'Identifies manufactured urgency triggers, fake security notifications, QR code lure payloads, and deceptive anchor text versus href destination mismatches.',
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
      title: 'Attachment Forensics Engine',
      subtitle: 'Air-Gapped Payload Triage',
      desc: 'Performs safe byte-level inspection: file magic signatures, RTLO unicode inversion (\\u202e), double extension tricks, VBA macros, and active scripts without sandbox execution.',
      input: 'Attachment byte stream, MIME headers',
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
  ];

  return (
    <div className="min-h-screen bg-[#f0fdf4] text-[#064e3b] font-sans antialiased selection:bg-[#86efac] selection:text-[#064e3b]">
      {/* 1. Header / Navigation */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-[#f0fdf4]/85 backdrop-blur-md border-b border-emerald-200/70 transition-all">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2.5 font-bold tracking-tight text-lg text-[#064e3b] group">
            <span className="text-emerald-500 group-hover:text-emerald-700 transition-colors font-mono font-semibold">\\</span>
            <span className="font-semibold text-[17px] tracking-[-0.02em]">PhishGuard<span className="text-emerald-600/70 font-normal">.ai</span></span>
          </Link>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-1 bg-[#dcfce7]/80 p-1.5 rounded-full border border-[#86efac]/70 text-xs font-medium text-[#065f46] shadow-xs">
            <a href="#how-it-works" className="px-3.5 py-1.5 rounded-full hover:text-[#064e3b] hover:bg-white transition-all">
              How It Works
            </a>
            <a href="#pipeline" className="px-3.5 py-1.5 rounded-full hover:text-[#064e3b] hover:bg-white transition-all">
              Five Agents
            </a>
            <a href="#faqs" className="px-3.5 py-1.5 rounded-full hover:text-[#064e3b] hover:bg-white transition-all">
              FAQs
            </a>
            <Link href="/overview" className="px-3.5 py-1.5 rounded-full hover:text-[#064e3b] hover:bg-white transition-all">
              Test Pipeline
            </Link>
          </nav>

          {/* Right Action Button - Light Green */}
          <div className="hidden md:flex items-center gap-3">
            <Link
              href="/investigate"
              className="inline-flex items-center justify-center bg-[#dcfce7] hover:bg-[#bbf7d0] text-[#064e3b] border border-[#86efac] px-5 py-2.5 rounded-full text-xs font-semibold shadow-xs transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Launch Pipeline
            </Link>
          </div>

          {/* Mobile Hamburger Toggle */}
          <div className="flex md:hidden items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 text-emerald-800 hover:text-emerald-950 rounded-md"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden bg-[#f0fdf4]/95 backdrop-blur-xl border-b border-emerald-200 px-6 py-4 flex flex-col gap-3 shadow-lg">
            <a
              href="#how-it-works"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-emerald-800 py-1.5"
            >
              How It Works
            </a>
            <a
              href="#pipeline"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-emerald-800 py-1.5"
            >
              Five Agents
            </a>
            <a
              href="#faqs"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-emerald-800 py-1.5"
            >
              FAQs
            </a>
            <Link
              href="/overview"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-emerald-800 py-1.5"
            >
              Test Pipeline
            </Link>
            <Link
              href="/investigate"
              onClick={() => setMobileMenuOpen(false)}
              className="w-full text-center bg-[#dcfce7] hover:bg-[#bbf7d0] text-[#064e3b] border border-[#86efac] py-2 rounded-full text-sm font-semibold mt-2"
            >
              Launch Pipeline
            </Link>
          </div>
        )}
      </header>

      {/* 2. Hero Section with 3D Stippled Particle Liquid GLSL Animated Background */}
      <section className="relative min-h-[85vh] md:min-h-[92vh] flex items-center justify-center pt-24 pb-20 px-6 overflow-hidden bg-[#f0fdf4]">
        {/* Three.js Stippled GLSL Liquid Canvas Background */}
        <LiquidShaderBackground className="absolute inset-0 z-0" />

        {/* Foreground Content */}
        <div className="relative z-10 max-w-4xl mx-auto text-center flex flex-col items-center">
          {/* Eyebrow Pill */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#dcfce7]/90 border border-[#86efac]/80 shadow-[0_2px_8px_rgba(16,185,129,0.08)] text-[#065f46] text-xs font-semibold mb-7 backdrop-blur-sm animate-fade-in">
            <span className="text-emerald-500 text-xs">✦</span>
            <span>Operational AI Infrastructure</span>
          </div>

          {/* Main Title */}
          <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-[68px] font-bold text-[#064e3b] tracking-[-0.035em] leading-[1.12] mb-6 max-w-3xl">
            Deploy{' '}
            <span className="font-serif-italic font-normal text-emerald-800">
              AI agents
            </span>{' '}
            across your security pipeline in minutes.
          </h1>

          {/* Subtitle */}
          <p className="text-base sm:text-lg text-emerald-900/80 max-w-2xl font-normal leading-relaxed mb-9">
            Automate multi-agent physical verification and security audits from inbound receiving to dispute resolution with immutable cryptographic evidence.
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row items-center gap-3.5 w-full sm:w-auto mb-10">
            <Link
              href="/investigate"
              className="w-full sm:w-auto inline-flex items-center justify-center bg-[#dcfce7] hover:bg-[#bbf7d0] text-[#064e3b] border border-[#86efac] px-7 py-3 rounded-full text-sm font-semibold shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Launch Pipeline Trace
            </Link>
            <Link
              href="/overview"
              className="w-full sm:w-auto inline-flex items-center justify-center bg-white/95 hover:bg-[#f0fdf4] text-[#065f46] border border-emerald-300 px-7 py-3 rounded-full text-sm font-medium shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              See How It Works
            </Link>
          </div>

          {/* Sub-badge: 5 Specialized Agents Orchestrated */}
          <div className="inline-flex items-center gap-2 text-xs font-medium text-emerald-800/80 tracking-wide">
            <span className="w-1.5 h-3 bg-emerald-600 rounded-[1px] inline-block" />
            <span>5 Specialized Agents Orchestrated</span>
          </div>
        </div>
      </section>

      {/* 3. System Architecture Section */}
      <section id="how-it-works" className="py-24 px-6 max-w-7xl mx-auto border-t border-emerald-200/70">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-emerald-700 mb-3 block">
            SYSTEM ARCHITECTURE
          </span>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#064e3b] mb-4">
            Centralized Orchestration & Cryptographic Evidence Chain
          </h2>
          <p className="text-emerald-900/75 text-sm sm:text-base leading-relaxed">
            Every incoming sample undergoes rigorous deterministic validation across 5 independent static engines.
            Verdicts are backed by discrete rule records before LLM explanation synthesis.
          </p>
        </div>

        {/* Dynamic Architectural Grid with Light Green Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="p-8 rounded-2xl bg-[#dcfce7]/50 border border-[#86efac]/80 shadow-sm hover:shadow-md hover:bg-[#dcfce7]/70 transition-all">
            <div className="w-10 h-10 rounded-xl bg-white border border-emerald-200 flex items-center justify-center text-emerald-800 mb-5 shadow-xs">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="text-lg font-semibold text-[#064e3b] mb-2">Air-Gapped Static Analysis</h3>
            <p className="text-sm text-emerald-800/80 leading-relaxed">
              Zero outbound network execution. Suspicious URLs are never fetched, attachments are never executed, and DNS is never probed during triage.
            </p>
          </div>

          <div className="p-8 rounded-2xl bg-[#dcfce7]/50 border border-[#86efac]/80 shadow-sm hover:shadow-md hover:bg-[#dcfce7]/70 transition-all">
            <div className="w-10 h-10 rounded-xl bg-white border border-emerald-200 flex items-center justify-center text-emerald-800 mb-5 shadow-xs">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h3 className="text-lg font-semibold text-[#064e3b] mb-2">Deterministic Scoring Engine</h3>
            <p className="text-sm text-emerald-800/80 leading-relaxed">
              Discrete component scoring separates Email Risk and Attachment Risk with correlated indicator damping to prevent false inflation.
            </p>
          </div>

          <div className="p-8 rounded-2xl bg-[#dcfce7]/50 border border-[#86efac]/80 shadow-sm hover:shadow-md hover:bg-[#dcfce7]/70 transition-all">
            <div className="w-10 h-10 rounded-xl bg-white border border-emerald-200 flex items-center justify-center text-emerald-800 mb-5 shadow-xs">
              <FileCode className="w-5 h-5" />
            </div>
            <h3 className="text-lg font-semibold text-[#064e3b] mb-2">Strict Anti-Hallucination Gate</h3>
            <p className="text-sm text-emerald-800/80 leading-relaxed">
              An automated evidence validator verifies all LLM claims against authoritative detection rules; unsupported claims are discarded.
            </p>
          </div>
        </div>
      </section>

      {/* 4. Five Core Security Engines Section with Light Green Theme */}
      <section id="pipeline" className="py-24 px-6 bg-[#dcfce7]/40 border-t border-[#86efac]/60">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-emerald-700 mb-3 block">
              DETECTION INFRASTRUCTURE
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#064e3b] mb-4">
              Five Autonomous Security Engines
            </h2>
            <p className="text-emerald-900/75 text-sm sm:text-base leading-relaxed">
              Each specialized module executes authoritative heuristic checks and returns structured forensic records.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {securityEngines.map((eng, idx) => (
              <div
                key={idx}
                className="bg-white/95 rounded-2xl p-7 border border-[#86efac]/70 shadow-sm hover:border-emerald-400 hover:shadow-md transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-[10px] font-mono font-semibold px-2.5 py-1 rounded-md bg-[#dcfce7] text-[#065f46] border border-[#86efac]/70">
                      {eng.stage}
                    </span>
                    <span className="text-[11px] font-medium text-emerald-600/70">
                      {eng.tag}
                    </span>
                  </div>
                  <h3 className="text-base font-semibold text-[#064e3b] mb-1">
                    {eng.title}
                  </h3>
                  <div className="text-xs font-medium text-emerald-700/80 mb-3">
                    {eng.subtitle}
                  </div>
                  <p className="text-xs text-emerald-900/75 leading-relaxed mb-6">
                    {eng.desc}
                  </p>
                </div>

                <div className="border-t border-emerald-100 pt-4 space-y-1.5 text-[11px] font-mono text-emerald-700/80">
                  <div className="flex justify-between">
                    <span className="text-emerald-500">IN:</span>
                    <span className="text-emerald-900 text-right truncate max-w-[200px]" title={eng.input}>{eng.input}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-emerald-500">OUT:</span>
                    <span className="text-[#064e3b] font-semibold">{eng.output}</span>
                  </div>
                </div>
              </div>
            ))}

            {/* Sixth Callout Card - Light Green Cyber Card */}
            <div className="bg-[#dcfce7] border-2 border-[#86efac] rounded-2xl p-7 text-[#064e3b] flex flex-col justify-between shadow-sm hover:border-emerald-400 hover:shadow-md transition-all">
              <div>
                <span className="text-[10px] font-mono font-semibold px-2.5 py-1 rounded-md bg-[#bbf7d0] text-[#065f46] border border-[#86efac] mb-4 inline-block">
                  ORCHESTRATION
                </span>
                <h3 className="text-lg font-bold text-[#064e3b] mb-2">LangGraph Multi-Agent Runtime</h3>
                <p className="text-xs text-[#065f46] leading-relaxed font-medium">
                  Coordinates Gemini 1.5 Flash and Groq Llama 3 with automatic state replay, deterministic fallbacks, and multi-tenant audit persistence in MongoDB Atlas.
                </p>
              </div>

              <Link
                href="/investigate"
                className="mt-6 inline-flex items-center justify-between bg-[#bbf7d0] text-[#064e3b] border border-[#86efac] px-4 py-2.5 rounded-lg text-xs font-semibold hover:bg-[#86efac] transition-all"
              >
                <span>Launch Pipeline</span>
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* 5. Frequently Asked Questions */}
      <section id="faqs" className="py-24 px-6 max-w-4xl mx-auto border-t border-emerald-200/70">
        <div className="text-center mb-16">
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-emerald-700 mb-3 block">
            ARCHITECTURE & COMPLIANCE
          </span>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#064e3b]">
            Frequently Answered Questions
          </h2>
        </div>

        <div className="space-y-4">
          {faqs.map((faq, idx) => (
            <div
              key={idx}
              className="border border-[#86efac]/70 rounded-xl overflow-hidden bg-white/95 shadow-2xs"
            >
              <button
                onClick={() => toggleFaq(idx)}
                className="w-full flex items-center justify-between p-5 text-left text-sm font-semibold text-[#064e3b] hover:bg-[#f0fdf4] transition-colors"
              >
                <span>{faq.q}</span>
                <ChevronDown
                  className={`w-4 h-4 text-emerald-600 transition-transform duration-200 ${
                    openFaq === idx ? 'rotate-180 text-emerald-800' : ''
                  }`}
                />
              </button>

              {openFaq === idx && (
                <div className="p-5 pt-0 text-xs sm:text-sm text-emerald-900/80 leading-relaxed border-t border-emerald-100 bg-[#f0fdf4]/80">
                  {faq.a}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* 6. Ready to Triage CTA with Light Green Background */}
      <section className="py-20 px-6 bg-[#ecfdf5] border-t border-[#a7f3d0] text-center">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-3xl font-bold tracking-tight text-[#064e3b] mb-4">
            Ready to inspect inbound security telemetry?
          </h2>
          <p className="text-emerald-800/80 text-sm sm:text-base max-w-xl mx-auto leading-relaxed mb-8">
            Launch the interactive Investigation console to analyze suspicious .eml samples, inspect
            static rule detections, and view the cryptographic trace.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3.5">
            <Link
              href="/investigate"
              className="w-full sm:w-auto inline-flex items-center justify-center bg-[#bbf7d0] hover:bg-[#86efac] text-[#064e3b] border border-[#4ade80] px-7 py-3 rounded-full text-sm font-semibold shadow-xs transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Open Investigation Console
            </Link>
            <Link
              href="/overview"
              className="w-full sm:w-auto inline-flex items-center justify-center bg-white hover:bg-[#dcfce7] text-[#064e3b] border border-[#86efac] px-7 py-3 rounded-full text-sm font-medium shadow-xs transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Control Tower Overview
            </Link>
          </div>
        </div>
      </section>

      {/* 7. Footer with Light Green Background */}
      <footer className="border-t border-[#bbf7d0] py-10 px-6 bg-[#f0fdf4] text-xs text-emerald-800/80">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-[#064e3b]">PhishGuard AI — Tier-2 & Tier-3 SOC Platform</span>
          </div>

          <div className="font-mono text-emerald-600/70 hidden md:block">
            Ingest &rarr; Headers | Body &rarr; URLs | Attachments &rarr; Deterministic Evidence
          </div>

          <div className="flex items-center gap-4 text-emerald-800/80">
            <span>Air-Gapped Static Analysis</span>
            <span>&bull;</span>
            <span>LangGraph Multi-Agent Orchestration</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
