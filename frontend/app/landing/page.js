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
    <div className="min-h-screen bg-white text-[#111827] font-sans antialiased selection:bg-neutral-900 selection:text-white">
      {/* 1. Header / Navigation */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-white/75 backdrop-blur-md border-b border-neutral-200/60 transition-all">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          {/* Logo */}
          <Link href="/landing" className="flex items-center gap-2.5 font-bold tracking-tight text-lg text-neutral-900 group">
            <span className="text-neutral-400 group-hover:text-neutral-900 transition-colors font-mono font-semibold">\\</span>
            <span className="font-semibold text-[17px] tracking-[-0.02em]">PhishGuard<span className="text-neutral-400 font-normal">.ai</span></span>
          </Link>

          {/* Desktop Navigation Links matching inspiration */}
          <nav className="hidden md:flex items-center gap-1 bg-neutral-100/80 p-1.5 rounded-full border border-neutral-200/80 text-xs font-medium text-neutral-600 shadow-sm">
            <a href="#how-it-works" className="px-3.5 py-1.5 rounded-full hover:text-neutral-900 hover:bg-white transition-all">
              How It Works
            </a>
            <a href="#pipeline" className="px-3.5 py-1.5 rounded-full hover:text-neutral-900 hover:bg-white transition-all">
              Five Agents
            </a>
            <a href="#faqs" className="px-3.5 py-1.5 rounded-full hover:text-neutral-900 hover:bg-white transition-all">
              FAQs
            </a>
            <Link href="/" className="px-3.5 py-1.5 rounded-full hover:text-neutral-900 hover:bg-white transition-all">
              Test Pipeline
            </Link>
          </nav>

          {/* Right Action Button matching inspiration */}
          <div className="hidden md:flex items-center gap-3">
            <Link
              href="/investigate"
              className="inline-flex items-center justify-center bg-neutral-950 text-white hover:bg-black px-5 py-2.5 rounded-full text-xs font-medium shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Launch Pipeline
            </Link>
          </div>

          {/* Mobile Hamburger Toggle */}
          <div className="flex md:hidden items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 text-neutral-700 hover:text-neutral-900 rounded-md"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden bg-white/95 backdrop-blur-xl border-b border-neutral-200 px-6 py-4 flex flex-col gap-3 shadow-lg">
            <a
              href="#how-it-works"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-neutral-700 py-1.5"
            >
              How It Works
            </a>
            <a
              href="#pipeline"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-neutral-700 py-1.5"
            >
              Five Agents
            </a>
            <a
              href="#faqs"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-neutral-700 py-1.5"
            >
              FAQs
            </a>
            <Link
              href="/"
              onClick={() => setMobileMenuOpen(false)}
              className="text-sm font-medium text-neutral-700 py-1.5"
            >
              Test Pipeline
            </Link>
            <Link
              href="/investigate"
              onClick={() => setMobileMenuOpen(false)}
              className="w-full text-center bg-neutral-950 text-white py-2 rounded-full text-sm font-medium mt-2"
            >
              Launch Pipeline
            </Link>
          </div>
        )}
      </header>

      {/* 2. Hero Section with 3D Stippled Particle Liquid GLSL Animated Background */}
      <section className="relative min-h-[85vh] md:min-h-[92vh] flex items-center justify-center pt-24 pb-20 px-6 overflow-hidden bg-white">
        {/* Three.js Stippled GLSL Liquid Canvas Background */}
        <LiquidShaderBackground className="absolute inset-0 z-0" />

        {/* Foreground Content */}
        <div className="relative z-10 max-w-4xl mx-auto text-center flex flex-col items-center">
          {/* Eyebrow Pill */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/90 border border-neutral-200/90 shadow-[0_2px_8px_rgba(0,0,0,0.03)] text-neutral-700 text-xs font-medium mb-7 backdrop-blur-sm animate-fade-in">
            <span className="text-neutral-400 text-xs">✦</span>
            <span>Operational AI Infrastructure</span>
          </div>

          {/* Main Title matching user reference recording with italic serif accent */}
          <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-[68px] font-bold text-neutral-900 tracking-[-0.035em] leading-[1.12] mb-6 max-w-3xl">
            Deploy{' '}
            <span className="font-serif-italic font-normal text-neutral-950">
              AI agents
            </span>{' '}
            across your security pipeline in minutes.
          </h1>

          {/* Subtitle matching inspiration */}
          <p className="text-base sm:text-lg text-neutral-600 max-w-2xl font-normal leading-relaxed mb-9">
            Automate multi-agent physical verification and security audits from inbound receiving to dispute resolution with immutable cryptographic evidence.
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row items-center gap-3.5 w-full sm:w-auto mb-10">
            <Link
              href="/investigate"
              className="w-full sm:w-auto inline-flex items-center justify-center bg-neutral-950 hover:bg-black text-white px-7 py-3 rounded-full text-sm font-medium shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Launch Pipeline Trace
            </Link>
            <Link
              href="#how-it-works"
              className="w-full sm:w-auto inline-flex items-center justify-center bg-white hover:bg-neutral-50 text-neutral-800 border border-neutral-300 px-7 py-3 rounded-full text-sm font-medium shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              See How It Works
            </Link>
          </div>

          {/* Sub-badge: 5 Specialized Agents Orchestrated matching inspiration */}
          <div className="inline-flex items-center gap-2 text-xs font-medium text-neutral-500 tracking-wide">
            <span className="w-1.5 h-3 bg-neutral-900 rounded-[1px] inline-block" />
            <span>5 Specialized Agents Orchestrated</span>
          </div>
        </div>
      </section>

      {/* 3. System Architecture Section */}
      <section id="how-it-works" className="py-24 px-6 max-w-7xl mx-auto border-t border-neutral-100">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-neutral-500 mb-3 block">
            SYSTEM ARCHITECTURE
          </span>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-neutral-900 mb-4">
            Centralized Orchestration & Cryptographic Evidence Chain
          </h2>
          <p className="text-neutral-600 text-sm sm:text-base leading-relaxed">
            Every attack vector is analyzed without network execution. The central Orchestrator
            coordinates deterministic security rules, validates SHA-256 evidence seals, updates
            immutable investigation states, and synthesizes explainable verdicts.
          </p>
        </div>

        {/* 3 Pillar Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1 */}
          <div className="p-8 rounded-2xl border border-neutral-200/80 bg-white shadow-[0_4px_20px_rgba(0,0,0,0.02)] hover:border-neutral-300 transition-all group">
            <span className="font-mono text-xs font-semibold text-neutral-400 mb-4 block group-hover:text-neutral-800 transition-colors">
              01
            </span>
            <h3 className="text-lg font-bold text-neutral-900 mb-3 tracking-tight">
              Deterministic Rule Grounding
            </h3>
            <p className="text-neutral-600 text-sm leading-relaxed">
              Over 30+ validated static security rules inspect email headers, body text, punycode
              URLs, and attachment byte payloads with transparent rule IDs and discrete component scoring.
            </p>
          </div>

          {/* Card 2 */}
          <div className="p-8 rounded-2xl border border-neutral-200/80 bg-white shadow-[0_4px_20px_rgba(0,0,0,0.02)] hover:border-neutral-300 transition-all group">
            <span className="font-mono text-xs font-semibold text-neutral-400 mb-4 block group-hover:text-neutral-800 transition-colors">
              02
            </span>
            <h3 className="text-lg font-bold text-neutral-900 mb-3 tracking-tight">
              Cryptographic Evidence Integrity
            </h3>
            <p className="text-neutral-600 text-sm leading-relaxed">
              Every judgment produces an immutable, content-addressed Evidence Record with canonical
              SHA-256 hashes. Downstream decisions cite verifiable upstream rule records.
            </p>
          </div>

          {/* Card 3 */}
          <div className="p-8 rounded-2xl border border-neutral-200/80 bg-white shadow-[0_4px_20px_rgba(0,0,0,0.02)] hover:border-neutral-300 transition-all group">
            <span className="font-mono text-xs font-semibold text-neutral-400 mb-4 block group-hover:text-neutral-800 transition-colors">
              03
            </span>
            <h3 className="text-lg font-bold text-neutral-900 mb-3 tracking-tight">
              Air-Gapped Static Analysis
            </h3>
            <p className="text-neutral-600 text-sm leading-relaxed">
              Zero network execution. Hyperlinks are never clicked, external tracking pixels are never
              fetched, and binary attachments are never executed or rendered.
            </p>
          </div>
        </div>
      </section>

      {/* 4. Modular Subsystems: The Five Autonomous Security Engines */}
      <section id="pipeline" className="py-24 px-6 bg-neutral-50/50 border-t border-neutral-100">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-16">
            <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-neutral-500 mb-3 block">
              MODULAR SUBSYSTEMS
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-neutral-900 mb-4">
              The Five Autonomous Security Engines
            </h2>
            <p className="text-neutral-600 text-sm sm:text-base leading-relaxed max-w-2xl mx-auto">
              From raw email ingestion through lexical URL decomposition to attachment byte forensics,
              each engine enforces a dedicated security boundary.
            </p>
          </div>

          {/* List of 5 Security Engine Cards */}
          <div className="flex flex-col gap-5">
            {securityEngines.map((engine, i) => (
              <div
                key={i}
                className="bg-white border border-neutral-200/80 rounded-2xl p-7 shadow-[0_2px_12px_rgba(0,0,0,0.02)] hover:shadow-[0_8px_24px_rgba(0,0,0,0.04)] hover:border-neutral-300 transition-all"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                  <span className="font-mono text-[10px] tracking-wider uppercase text-neutral-400 font-semibold">
                    {engine.stage}
                  </span>
                  <span className="px-2.5 py-1 rounded-full bg-neutral-100 text-neutral-600 text-[11px] font-medium">
                    {engine.tag}
                  </span>
                </div>

                <h3 className="text-xl font-bold text-neutral-900 tracking-tight">
                  {engine.title}
                </h3>
                <span className="text-xs font-medium text-neutral-500 mb-3 block">
                  {engine.subtitle}
                </span>

                <p className="text-neutral-600 text-sm leading-relaxed mb-5">
                  {engine.desc}
                </p>

                <div className="pt-4 border-t border-neutral-100 flex flex-col sm:flex-row gap-3 sm:gap-6 text-xs text-neutral-500">
                  <div>
                    <span className="font-semibold text-neutral-700">Input Data: </span>
                    <span>{engine.input}</span>
                  </div>
                  <div>
                    <span className="font-semibold text-neutral-700">Output Record: </span>
                    <span className="font-mono text-neutral-800">{engine.output}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 5. Frequently Asked Questions */}
      <section id="faqs" className="py-24 px-6 max-w-4xl mx-auto border-t border-neutral-100">
        <div className="text-center mb-16">
          <span className="text-[11px] font-semibold tracking-[0.2em] uppercase text-neutral-500 mb-3 block">
            COMMON INQUIRIES
          </span>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-neutral-900">
            Frequently Asked Questions
          </h2>
        </div>

        <div className="flex flex-col gap-4">
          {faqs.map((faq, idx) => {
            const isOpen = openFaq === idx;
            return (
              <div
                key={idx}
                className="border border-neutral-200/80 rounded-2xl bg-white overflow-hidden transition-all shadow-[0_2px_8px_rgba(0,0,0,0.02)]"
              >
                <button
                  onClick={() => toggleFaq(idx)}
                  className="w-full text-left p-6 flex items-center justify-between gap-4 font-semibold text-neutral-900 text-base hover:text-black"
                >
                  <span>{faq.q}</span>
                  <ChevronDown
                    className={`w-4 h-4 text-neutral-400 transition-transform duration-200 flex-shrink-0 ${
                      isOpen ? 'transform rotate-180' : ''
                    }`}
                  />
                </button>
                {isOpen && (
                  <div className="px-6 pb-6 pt-1 text-sm text-neutral-600 leading-relaxed border-t border-neutral-100/60 animate-fade-in">
                    {faq.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* 6. Ready to Execute Live Threat Investigation Banner */}
      <section className="py-16 px-6 max-w-5xl mx-auto">
        <div className="bg-neutral-50/80 border border-neutral-200/90 rounded-3xl p-10 sm:p-14 text-center shadow-[0_4px_24px_rgba(0,0,0,0.03)] flex flex-col items-center">
          <h2 className="text-2xl sm:text-3xl font-bold text-neutral-900 tracking-tight mb-3">
            Ready to Execute Live Threat Investigation?
          </h2>
          <p className="text-neutral-600 text-sm sm:text-base max-w-xl mx-auto leading-relaxed mb-8">
            Launch the interactive Investigation console to analyze suspicious .eml samples, inspect
            static rule detections, and view the cryptographic trace.
          </p>
          <Link
            href="/investigate"
            className="inline-flex items-center justify-center bg-neutral-900 hover:bg-black text-white px-7 py-3 rounded-lg text-sm font-medium shadow-md transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            Open Investigation Console
          </Link>
        </div>
      </section>

      {/* 7. Footer */}
      <footer className="border-t border-neutral-200/70 py-10 px-6 bg-white text-xs text-neutral-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-neutral-700">PhishGuard AI — Tier-2 & Tier-3 SOC Platform</span>
          </div>

          <div className="font-mono text-neutral-400 hidden md:block">
            Ingest &rarr; Headers | Body &rarr; URLs | Attachments &rarr; Deterministic Evidence
          </div>

          <div className="flex items-center gap-4 text-neutral-500">
            <span>Air-Gapped Static Analysis</span>
            <span>&bull;</span>
            <span>LangGraph Multi-Agent Orchestration</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
