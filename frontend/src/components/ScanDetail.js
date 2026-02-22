"use client";
import { useEffect, useState } from 'react';
import { getScanResults, getAiSummary, cancelScan } from '@/lib/api';
import './ScanDetail.css';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export default function ScanDetail({ scan, onClose, onScanUpdate }) {
    const [results, setResults] = useState(null);
    const [aiSummary, setAiSummary] = useState(null);
    const [loading, setLoading] = useState(true);
    const [cancelling, setCancelling] = useState(false);

    useEffect(() => {
        if (!scan) return;
        setLoading(true);

        Promise.allSettled([
            getScanResults(scan.id),
            getAiSummary(scan.id),
        ]).then(([resultsRes, aiRes]) => {
            if (resultsRes.status === 'fulfilled') setResults(resultsRes.value);
            if (aiRes.status === 'fulfilled') setAiSummary(aiRes.value);
            setLoading(false);
        });
    }, [scan]);

    const handleCancel = async () => {
        if (!scan) return;
        setCancelling(true);
        try {
            const updated = await cancelScan(scan.id);
            onScanUpdate?.(updated);
        } catch (err) {
            console.error('Failed to cancel:', err);
        }
        setCancelling(false);
    };

    if (!scan) return null;

    const isActive = ['queued', 'running'].includes(scan.status);
    const riskScore = scan.risk_score != null ? Math.round(scan.risk_score) : null;
    const totalVulns = results?.summary?.total_findings ?? 0;
    const bySeverity = results?.summary?.by_severity ?? {};
    const maxCount = Math.max(...Object.values(bySeverity), 1);

    const getScoreColor = (s) => {
        if (s == null) return '';
        if (s >= 80) return 'green';
        if (s >= 50) return 'orange';
        return 'red';
    };

    return (
        <>
            <div className="detail-overlay" onClick={onClose} />
            <div className="detail-panel">
                <div className="detail-header">
                    <h2>Scan Details</h2>
                    <button className="detail-close" onClick={onClose}>
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                        </svg>
                    </button>
                </div>

                <div className="detail-body">
                    {/* Info grid */}
                    <div className="detail-info">
                        <div className="detail-info-item">
                            <label>Target</label>
                            <div className="value" style={{ fontSize: '13px', wordBreak: 'break-all' }}>{scan.target_url}</div>
                        </div>
                        <div className="detail-info-item">
                            <label>Risk Score</label>
                            <div className={`value ${getScoreColor(riskScore)}`}>{riskScore ?? '—'}</div>
                        </div>
                        <div className="detail-info-item">
                            <label>Scan Type</label>
                            <div className="value">{scan.scan_type?.toUpperCase()}</div>
                        </div>
                        <div className="detail-info-item">
                            <label>Status</label>
                            <div className={`value ${scan.status === 'completed' ? 'green' : scan.status === 'failed' ? 'red' : 'orange'}`}>
                                {scan.status?.toUpperCase()}
                            </div>
                        </div>
                    </div>

                    {loading ? (
                        <div className="detail-loading">
                            <div className="spinner"></div>
                            Loading results...
                        </div>
                    ) : (
                        <>
                            {/* Severity Breakdown */}
                            {totalVulns > 0 && (
                                <div className="detail-section">
                                    <h3>Severity Breakdown ({totalVulns} findings)</h3>
                                    <div className="severity-bars">
                                        {SEVERITY_ORDER.map((sev) => {
                                            const count = bySeverity[sev] || 0;
                                            if (count === 0) return null;
                                            return (
                                                <div key={sev} className="severity-bar">
                                                    <span className={`severity-label ${sev}`}>{sev}</span>
                                                    <div className="severity-track">
                                                        <div className={`severity-fill ${sev}`} style={{ width: `${(count / maxCount) * 100}%` }}></div>
                                                    </div>
                                                    <span className="severity-count">{count}</span>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            )}

                            {/* Vulnerabilities */}
                            {results?.vulnerabilities?.length > 0 && (
                                <div className="detail-section">
                                    <h3>Vulnerabilities</h3>
                                    <div className="vuln-list">
                                        {results.vulnerabilities.slice(0, 20).map((v) => (
                                            <div key={v.id} className="vuln-item">
                                                <div className="vuln-item-header">
                                                    <h4>{v.title}</h4>
                                                    <span className={`vuln-severity-tag ${v.severity}`}>{v.severity}</span>
                                                </div>
                                                {v.description && <p>{v.description}</p>}
                                                <div className="vuln-meta">
                                                    {v.cvss_score && <span>CVSS: {v.cvss_score}</span>}
                                                    {v.location && <span>{v.location}</span>}
                                                    {v.detection_source && <span>Source: {v.detection_source}</span>}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* AI Summary */}
                            {aiSummary && (
                                <div className="detail-section">
                                    <h3>AI Analysis</h3>
                                    <div className="ai-summary-text">
                                        {typeof aiSummary === 'string' ? aiSummary : JSON.stringify(aiSummary, null, 2)}
                                    </div>
                                </div>
                            )}

                            {totalVulns === 0 && !aiSummary && (
                                <div className="detail-empty">
                                    {isActive ? 'Scan is still in progress. Results will appear here once complete.' : 'No vulnerabilities found for this scan.'}
                                </div>
                            )}
                        </>
                    )}
                </div>

                {/* Actions */}
                <div className="detail-actions">
                    {isActive && (
                        <button className="detail-action-btn danger" onClick={handleCancel} disabled={cancelling}>
                            {cancelling ? 'Cancelling...' : 'Cancel Scan'}
                        </button>
                    )}
                    <button className="detail-action-btn secondary" onClick={onClose}>Close</button>
                </div>
            </div>
        </>
    );
}
