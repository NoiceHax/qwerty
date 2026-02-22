"use client";
import './home.css';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { getHealth } from '@/lib/api';

const terminalLines = [
  { type: 'prompt', text: '→ cyberguard scan --target production-api-v4' },
  { type: 'info', text: '[INFO] Initializing security engine...' },
  { type: 'info', text: '[INFO] Running 14,204 vulnerability heuristics...' },
  { type: 'info', text: '[SCANNING] Analyzing cluster: kubernetes-cl...' },
];

export default function HomePage() {
  const router = useRouter();
  const [visibleLines, setVisibleLines] = useState([]);
  const [showAlert, setShowAlert] = useState(false);
  const [showCursor, setShowCursor] = useState(false);
  const [backendStatus, setBackendStatus] = useState(null);

  useEffect(() => {
    getHealth()
      .then((data) => setBackendStatus(data))
      .catch(() => setBackendStatus(null));
  }, []);

  useEffect(() => {
    const timers = [];
    terminalLines.forEach((line, i) => {
      timers.push(setTimeout(() => {
        setVisibleLines(prev => [...prev, line]);
      }, 800 + i * 600));
    });
    timers.push(setTimeout(() => setShowAlert(true), 800 + terminalLines.length * 600 + 400));
    timers.push(setTimeout(() => setShowCursor(true), 800 + terminalLines.length * 600 + 1000));
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div className="home-page">
      {/* Navbar */}
      <nav className="navbar">
        <div className="nav-brand">
          <div className="nav-brand-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          CyberGuard
        </div>
        <div className="nav-links">
          <a href="#">Solutions</a>
          <a href="#">Intelligence</a>
          <a href="#">Pricing</a>
          <a href="#">Docs</a>
        </div>
        <div className="nav-actions">
          <button className="nav-login" onClick={() => router.push('/login')}>Login</button>
          <button className="nav-cta" onClick={() => router.push('/login')}>Get Started</button>
        </div>
      </nav>

      {/* Hero */}
      <section className="hero">
        <div className="hero-badge">
          <span className="dot"></span>
          V2.0 NOW LIVE
        </div>
        <h1>
          Next-Gen<br />
          <span className="gradient-text">Vulnerability Intelligence</span>
        </h1>
        <p className="hero-subtitle">
          Identify, triage, and remediate threats before they reach production.
          The automated command center for elite security engineering teams.
        </p>
        <div className="hero-actions">
          <button className="hero-btn-primary" onClick={() => router.push('/login')}>
            <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
            Login with GitHub
          </button>
          <button className="hero-btn-secondary" onClick={() => router.push('/dashboard')}>View Interactive Demo</button>
        </div>
      </section>

      {/* Terminal */}
      <section className="terminal-section">
        <div className="terminal-window">
          <div className="terminal-header">
            <span className="terminal-dot red"></span>
            <span className="terminal-dot yellow"></span>
            <span className="terminal-dot green"></span>
            <span className="terminal-title">ssh — 43424</span>
          </div>
          <div className="terminal-body">
            {visibleLines.map((line, i) => (
              <div key={i} className="terminal-line" style={{ animation: 'fadeIn 0.3s ease-out' }}>
                {line.type === 'prompt' ? (
                  <span><span className="terminal-prompt">→ </span><span className="terminal-cmd">{line.text.replace('→ ', '')}</span></span>
                ) : (
                  <span className="terminal-info">{line.text}</span>
                )}
              </div>
            ))}
            {showAlert && (
              <div className="terminal-alert-box" style={{ animation: 'fadeIn 0.4s ease-out' }}>
                <div className="terminal-alert-title">⚠ CRITICAL VULNERABILITY DETECTED</div>
                <div className="terminal-alert-detail">
                  CVE CVE-2024-1091<br />
                  Scope: express-session @ 1.17.3<br />
                  Type: Remote Code Execution
                  <span className="terminal-alert-badge">IMMEDIATE ACTION REQUIRED</span>
                </div>
              </div>
            )}
            {showCursor && (
              <div className="terminal-cursor">
                <span className="arrow">→</span>
                <span className="blink"></span>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="features-section">
        <h2>Enterprise-Grade Defense</h2>
        <p>Built for the modern DevSecOps workflow with high-performance scanning.</p>
        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76" />
              </svg>
            </div>
            <h3>Real-time Threat Mapping</h3>
            <p>Visualize your entire attack surface in real-time with automated discovery and dependency graph analysis.</p>
          </div>
          <div className="feature-card">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
              </svg>
            </div>
            <h3>Automated Patch Intelligence</h3>
            <p>Get instant remediation steps and automated pull requests for known vulnerabilities across your stack.</p>
          </div>
          <div className="feature-card">
            <div className="feature-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                <line x1="8" y1="21" x2="16" y2="21" />
                <line x1="12" y1="17" x2="12" y2="21" />
              </svg>
            </div>
            <h3>CI/CD Security Gates</h3>
            <p>Prevent insecure code from ever reaching production with custom policies and blocking rules.</p>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="cta-section">
        <div className="cta-banner">
          <h2>Secure your infrastructure today.</h2>
          <p>Join 500+ elite security teams securing their production environments with CyberGuard.</p>
          <div className="cta-actions">
            <button className="cta-primary" onClick={() => router.push('/login')}>Start Scanning Now</button>
            <button className="cta-secondary">Talk to Sales</button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="home-footer">
        <div className="footer-brand">
          <div className="footer-brand-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          CyberGuard
        </div>
        <div className="footer-links">
          <a href="#">Privacy Policy</a>
          <a href="#">Terms of Service</a>
          <a href="#">Security Status</a>
          <a href="#">Cookie Settings</a>
        </div>
        <span className="footer-copy">© 2024 CyberGuard Intelligence Inc.</span>
      </footer>
    </div>
  );
}
