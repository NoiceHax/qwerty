"use client";
import { useState } from 'react';
import { createScan } from '@/lib/api';
import './ScanModal.css';

export default function ScanModal({ onClose, onCreated, defaultTargetType = 'url' }) {
    const [targetUrl, setTargetUrl] = useState('');
    const [scanType, setScanType] = useState('dynamic');
    const [targetType, setTargetType] = useState(defaultTargetType);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!targetUrl.trim()) {
            setError('Please enter a target URL');
            return;
        }
        setLoading(true);
        setError('');
        try {
            const scan = await createScan({
                target_url: targetUrl.trim(),
                scan_type: scanType,
                target_type: targetType,
            });
            onCreated?.(scan);
            onClose();
        } catch (err) {
            setError(err.message || 'Failed to create scan');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
            <div className="modal">
                <h2>{targetType === 'repo' ? 'New Repository Scan' : 'New Website Scan'}</h2>
                <p>Enter the target to scan for vulnerabilities.</p>

                <form onSubmit={handleSubmit}>
                    <div className="modal-field">
                        <label>Target {targetType === 'repo' ? 'Repository URL' : 'URL'}</label>
                        <input
                            type="text"
                            placeholder={targetType === 'repo' ? 'https://github.com/org/repo' : 'https://example.com'}
                            value={targetUrl}
                            onChange={(e) => setTargetUrl(e.target.value)}
                            autoFocus
                        />
                    </div>

                    <div className="modal-field">
                        <label>Target Type</label>
                        <div className="type-selector">
                            <button type="button" className={`type-option ${targetType === 'url' ? 'active' : ''}`} onClick={() => setTargetType('url')}>
                                Website URL
                            </button>
                            <button type="button" className={`type-option ${targetType === 'repo' ? 'active' : ''}`} onClick={() => setTargetType('repo')}>
                                GitHub Repo
                            </button>
                        </div>
                    </div>

                    <div className="modal-field">
                        <label>Scan Type</label>
                        <div className="type-selector">
                            <button type="button" className={`type-option ${scanType === 'dynamic' ? 'active' : ''}`} onClick={() => setScanType('dynamic')}>
                                Dynamic
                            </button>
                            <button type="button" className={`type-option ${scanType === 'static' ? 'active' : ''}`} onClick={() => setScanType('static')}>
                                Static
                            </button>
                            <button type="button" className={`type-option ${scanType === 'full' ? 'active' : ''}`} onClick={() => setScanType('full')}>
                                Full
                            </button>
                        </div>
                    </div>

                    {error && <div className="modal-error">{error}</div>}

                    <div className="modal-actions">
                        <button type="button" className="modal-cancel" onClick={onClose}>Cancel</button>
                        <button type="submit" className="modal-submit" disabled={loading}>
                            {loading ? 'Starting Scan...' : 'Start Scan'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
