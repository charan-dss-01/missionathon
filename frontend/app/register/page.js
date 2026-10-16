'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, Lock, Mail, User, Eye, EyeOff, AlertTriangle, ArrowRight, CheckCircle2, Check, X } from 'lucide-react';
import { useAuth } from '@/components/AuthProvider';

export default function RegisterPage() {
  const router = useRouter();
  const { register } = useAuth();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Password rules
  const hasMinLength = password.length >= 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasDigitOrSpecial = /[\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  const passwordsMatch = password && confirmPassword && password === confirmPassword;
  const isValid = hasMinLength && hasUppercase && hasLowercase && hasDigitOrSpecial && passwordsMatch;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!name.trim()) {
      setError('Please provide your full name.');
      return;
    }
    if (!email.trim()) {
      setError('Please enter a valid email address.');
      return;
    }
    if (!hasMinLength || !hasUppercase || !hasLowercase || !hasDigitOrSpecial) {
      setError('Please ensure your password satisfies all security criteria.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      await register(name.trim(), email.trim(), password);
      setSuccess('Account provisioned successfully in MongoDB. Launching console...');
      setTimeout(() => {
        router.push('/');
      }, 600);
    } catch (err) {
      setError(err.message || 'Registration failed. Please review your details.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-[calc(100vh-14rem)] py-12">
      <div className="w-full max-w-md space-y-6">
        {/* Card Header */}
        <div className="text-center space-y-1">
          <div className="inline-flex items-center justify-center p-3 rounded-md bg-card border border-border text-primary mb-2">
            <Shield className="w-6 h-6 stroke-[1.8]" />
          </div>
          <span className="eyebrow block">TENANT ONBOARDING</span>
          <h1 className="text-2xl font-bold text-foreground">
            Register SOC Analyst<span className="heading-dot">.</span>
          </h1>
          <p className="text-xs text-muted-foreground">
            Create an isolated tenant account on PhishGuard Control Tower.
          </p>
        </div>

        {/* Register Form Container */}
        <div className="bg-card border border-border rounded-md p-6 sm:p-7 shadow-sm space-y-4">
          {error && (
            <div className="p-3 rounded border border-danger/30 bg-danger/10 text-danger text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="p-3 rounded border border-success/30 bg-success/10 text-success text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{success}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1.5">
                Full Name
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-muted-foreground absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Security Analyst"
                  required
                  className="w-full pl-9 pr-3 py-2 rounded bg-background border border-input text-foreground placeholder:text-muted-foreground text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1.5">
                Email Address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-muted-foreground absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@phishguard.ai"
                  required
                  className="w-full pl-9 pr-3 py-2 rounded bg-background border border-input text-foreground placeholder:text-muted-foreground text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-muted-foreground absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="At least 8 chars, Aa1"
                  required
                  className="w-full pl-9 pr-10 py-2 rounded bg-background border border-input text-foreground placeholder:text-muted-foreground text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2.5 text-muted-foreground hover:text-foreground cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1.5">
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-muted-foreground absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Repeat password"
                  required
                  className="w-full pl-9 pr-3 py-2 rounded bg-background border border-input text-foreground placeholder:text-muted-foreground text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            </div>

            {/* Criteria Checklist */}
            <div className="p-3 rounded bg-background border border-border space-y-1.5 text-[11px]">
              <span className="text-muted-foreground font-mono text-[10px] uppercase font-semibold block">
                Security Criteria
              </span>
              <div className="grid grid-cols-2 gap-1 text-[11px]">
                <div className={`flex items-center gap-1.5 ${hasMinLength ? 'text-success' : 'text-muted-foreground'}`}>
                  {hasMinLength ? <Check className="w-3 h-3 text-success" /> : <span className="w-3 h-3 rounded-full border border-border block" />}
                  <span>8+ characters</span>
                </div>
                <div className={`flex items-center gap-1.5 ${hasUppercase ? 'text-success' : 'text-muted-foreground'}`}>
                  {hasUppercase ? <Check className="w-3 h-3 text-success" /> : <span className="w-3 h-3 rounded-full border border-border block" />}
                  <span>Uppercase letter</span>
                </div>
                <div className={`flex items-center gap-1.5 ${hasLowercase ? 'text-success' : 'text-muted-foreground'}`}>
                  {hasLowercase ? <Check className="w-3 h-3 text-success" /> : <span className="w-3 h-3 rounded-full border border-border block" />}
                  <span>Lowercase letter</span>
                </div>
                <div className={`flex items-center gap-1.5 ${hasDigitOrSpecial ? 'text-success' : 'text-muted-foreground'}`}>
                  {hasDigitOrSpecial ? <Check className="w-3 h-3 text-success" /> : <span className="w-3 h-3 rounded-full border border-border block" />}
                  <span>Number or symbol</span>
                </div>
              </div>
              {confirmPassword && (
                <div className={`pt-1 flex items-center gap-1.5 ${passwordsMatch ? 'text-success' : 'text-danger'}`}>
                  {passwordsMatch ? <Check className="w-3 h-3 text-success" /> : <X className="w-3 h-3 text-danger" />}
                  <span>{passwordsMatch ? 'Passwords match' : 'Passwords do not match'}</span>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={loading || !isValid}
              className="w-full mt-2 py-2 px-4 rounded bg-primary text-primary-foreground font-medium text-xs tracking-wide hover:opacity-90 transition disabled:opacity-40 cursor-pointer flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                  <span>Provisioning Account...</span>
                </>
              ) : (
                <>
                  <span>Create Account &amp; Enter SOC</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>

          {/* Login link */}
          <div className="pt-4 border-t border-border text-center text-xs text-muted-foreground">
            Already have an account?{' '}
            <Link
              href="/login"
              className="text-primary hover:underline font-semibold"
            >
              Sign In
            </Link>
          </div>
        </div>

        {/* Security badge footer */}
        <div className="text-center text-[11px] text-muted-foreground flex items-center justify-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-primary" />
          <span>Bcrypt Password Salting · Zero Plaintext Storage</span>
        </div>
      </div>
    </div>
  );
}
