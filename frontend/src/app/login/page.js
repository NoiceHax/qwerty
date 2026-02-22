"use client";
import './login.css';
import { useEffect, useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';


const GITHUB_CLIENT_ID = "Ov23lik7WUwQYjJsz774";

function LoginPageInner() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const [error, setError] = useState(null);

    // Check if user is already logged in
    useEffect(() => {
        fetch('/api/auth/me')
            .then(res => res.ok ? res.json() : null)
            .then(data => {
                if (data?.authenticated) router.replace('/dashboard');
            })
            .catch(() => { });
    }, [router]);


    // Check for OAuth errors in URL
    useEffect(() => {
        const err = searchParams.get('error');
        if (err) {
            const messages = {
                no_code: 'Authorization was cancelled.',
                bad_verification_code: 'Authorization code expired. Please try again.',
                server_error: 'Something went wrong. Please try again.',
            };
            setError(messages[err] || `Login failed: ${err}`);
        }
    }, [searchParams]);

    const handleLogin = () => {
        const params = new URLSearchParams({
            client_id: GITHUB_CLIENT_ID,
            scope: 'read:user user:email',
        });
        window.location.href = `https://github.com/login/oauth/authorize?${params}`;
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
                <h1>qwerty</h1>
                <p>Enterprise Security Perimeter</p>
            </div>

            {/* Login Card */}
            <div className="login-card">
                <h2>Secure Access</h2>
                <p>Connect your GitHub account to continue to the dashboard.</p>

                {error && (
                    <div style={{
                        background: 'rgba(239,68,68,0.1)',
                        border: '1px solid rgba(239,68,68,0.3)',
                        borderRadius: '8px',
                        padding: '12px 16px',
                        marginBottom: '16px',
                        color: '#ef4444',
                        fontSize: '0.85rem',
                    }}>
                        {error}
                    </div>
                )}

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



            {/* Footer */}
            <footer className="login-footer">
                <span>© 2024 QWERTY INC.</span>
                <div className="login-footer-links">
                    <a href="#">PRIVACY POLICY</a>
                    <a href="#">TERMS OF SERVICE</a>
                    <a href="#">STATUS</a>
                </div>
            </footer>
        </div>
    );
}

export default function LoginPage() {
    return (
        <Suspense fallback={<div className="login-page" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}><p>Loading...</p></div>}>
            <LoginPageInner />
        </Suspense>
    );
}
