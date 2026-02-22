"use client";
import './login.css';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { getHealth } from '@/lib/api';

export default function LoginPage() {
    const router = useRouter();
    const [systemStatus, setSystemStatus] = useState('checking');

    useEffect(() => {
        getHealth()
            .then(() => setSystemStatus('operational'))
            .catch(() => setSystemStatus('offline'));
    }, []);

    const handleLogin = () => {
        // Placeholder: skip to dashboard (replace with real OAuth later)
        router.push('/dashboard');
    };

    return (
        <div className="login-page">
            {/* Brand */}
            <div className="login-brand">
                <div className="login-logo">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        <path d="M9 12l2 2 4-4" />
                    </svg>
                </div>
                <h1>CyberSafe</h1>
                <p>Enterprise Security Perimeter</p>
            </div>

            {/* Login Card */}
            <div className="login-card">
                <h2>Secure Access</h2>
                <p>Connect your account to continue to the dashboard.</p>

                <button className="github-btn" onClick={handleLogin}>
                    <svg viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                    </svg>
                    Continue with GitHub
                </button>

                <div className="permissions-divider">
                    <span>PERMISSIONS NOTICE</span>
                </div>

                <div className="permissions-box">
                    <div className="permissions-icon">
                        <svg viewBox="0 0 24 24" fill="currentColor">
                            <circle cx="12" cy="12" r="10" />
                            <path d="M12 16v-4M12 8h.01" stroke="white" strokeWidth="2" strokeLinecap="round" />
                        </svg>
                    </div>
                    <div className="permissions-text">
                        <h4>Repository Scopes</h4>
                        <p>We only request read-access to your public repositories and primary email. <span className="highlight">No code will be modified or deleted.</span></p>
                    </div>
                </div>

                <a href="#" className="learn-more">
                    Learn more about security protocols
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M5 12h14M12 5l7 7-7 7" />
                    </svg>
                </a>
            </div>

            {/* System Status */}
            <div className={`system-badge ${systemStatus === 'offline' ? 'offline' : ''}`}
                style={systemStatus === 'offline' ? { background: 'rgba(239,68,68,0.1)', borderColor: 'rgba(239,68,68,0.2)', color: '#ef4444' } : systemStatus === 'checking' ? { background: 'rgba(234,179,8,0.1)', borderColor: 'rgba(234,179,8,0.2)', color: '#eab308' } : {}}
            >
                <span className="dot" style={systemStatus === 'offline' ? { background: '#ef4444' } : systemStatus === 'checking' ? { background: '#eab308' } : {}}></span>
                {systemStatus === 'operational' ? 'SYSTEM OPERATIONAL' : systemStatus === 'offline' ? 'SYSTEM OFFLINE' : 'CHECKING STATUS...'}
            </div>

            {/* Footer */}
            <footer className="login-footer">
                <span>© 2024 CYBERSAFE TECHNOLOGIES INC.</span>
                <div className="login-footer-links">
                    <a href="#">PRIVACY POLICY</a>
                    <a href="#">TERMS OF SERVICE</a>
                    <a href="#">STATUS</a>
                </div>
            </footer>
        </div>
    );
}
