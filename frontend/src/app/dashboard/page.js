"use client";
import './dashboard.css';
import { useEffect, useState, useRef, useCallback } from 'react';
import { listScans, getWsUrl } from '@/lib/api';
import ScanModal from '@/components/ScanModal';
import ScanDetail from '@/components/ScanDetail';

const STATUS_MAP = {
    queued: { label: 'QUEUED', cls: 'active' },
    running: { label: 'ACTIVE SCAN', cls: 'active' },
    completed: { label: 'COMPLETED', cls: 'completed' },
    failed: { label: 'FAILED', cls: 'critical' },
    cancelled: { label: 'CANCELLED', cls: 'critical' },
};

const TYPE_LABELS = {
    dynamic: 'DAST Full Scan',
    static: 'SAST Audit',
    full: 'Full Scan',
};

function getScoreClass(score) {
    if (score == null) return 'medium';
    if (score >= 80) return 'high';
    if (score >= 50) return 'medium';
    return 'low';
}

function getTargetIcon(scan) {
    if (scan.target_type === 'repo') return { icon: 'code', color: 'blue' };
    const status = scan.status;
    if (status === 'failed' || (scan.posture_rating && scan.posture_rating.includes('critical'))) return { icon: 'warning', color: 'red' };
    if (status === 'completed') return { icon: 'shield', color: 'green' };
    if (status === 'running' || status === 'queued') return { icon: 'container', color: 'orange' };
    return { icon: 'shield', color: 'orange' };
}

function timeAgo(dateStr) {
    if (!dateStr) return '—';
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins} min${mins > 1 ? 's' : ''} ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    const days = Math.floor(hours / 24);
    return `${days} day${days > 1 ? 's' : ''} ago`;
}

function ScanIcon({ type }) {
    switch (type) {
        case 'shield':
            return (
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
            );
        case 'code':
            return (
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
                </svg>
            );
        case 'warning':
            return (
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
            );
        case 'container':
            return (
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
                    <polyline points="3.27 6.96 12 12.01 20.73 6.96" /><line x1="12" y1="22.08" x2="12" y2="12" />
                </svg>
            );
        default:
            return null;
    }
}

export default function DashboardPage() {
    const [scans, setScans] = useState([]);
    const [totalScans, setTotalScans] = useState(0);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(null); // null | 'url' | 'repo'
    const [selectedScan, setSelectedScan] = useState(null);
    const [wsLogs, setWsLogs] = useState([]);
    const wsRef = useRef(null);
    const logsEndRef = useRef(null);

    // Fetch scans
    const fetchScans = useCallback(async () => {
        try {
            const data = await listScans({ limit: 50 });
            setScans(data.scans || []);
            setTotalScans(data.total || 0);
        } catch (err) {
            console.error('Failed to fetch scans:', err);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchScans();
        const interval = setInterval(fetchScans, 10000); // poll every 10s
        return () => clearInterval(interval);
    }, [fetchScans]);

    // WebSocket for active scan logs
    useEffect(() => {
        const activeScan = scans.find(s => s.status === 'running');
        if (!activeScan) {
            if (wsRef.current) {
                wsRef.current.close();
                wsRef.current = null;
            }
            return;
        }

        // Don't reconnect if already connected to same scan
        if (wsRef.current && wsRef.current._scanId === activeScan.id) return;

        if (wsRef.current) wsRef.current.close();

        const ws = new WebSocket(getWsUrl(activeScan.id));
        ws._scanId = activeScan.id;
        wsRef.current = ws;

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'log') {
                    const logEntry = {
                        time: new Date(msg.data.timestamp).toLocaleTimeString('en-US', { hour12: false }),
                        tag: msg.data.level?.toUpperCase() || 'INFO',
                        tagClass: msg.data.level || 'info',
                        msg: msg.data.message,
                        isError: msg.data.level === 'error',
                    };
                    setWsLogs(prev => [...prev.slice(-100), logEntry]);
                } else if (msg.type === 'done') {
                    fetchScans();
                }
            } catch { }
        };

        ws.onerror = () => { };
        ws.onclose = () => { };

        return () => {
            ws.close();
            wsRef.current = null;
        };
    }, [scans, fetchScans]);

    // Auto-scroll logs
    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [wsLogs]);

    const handleScanCreated = (newScan) => {
        setScans(prev => [newScan, ...prev]);
        setWsLogs([]);
        fetchScans();
    };

    const handleScanUpdate = (updatedScan) => {
        setScans(prev => prev.map(s => s.id === updatedScan.id ? updatedScan : s));
        setSelectedScan(updatedScan);
    };

    const activeCount = scans.filter(s => ['running', 'queued'].includes(s.status)).length;

    // Fallback logs when no WebSocket is active
    const displayLogs = wsLogs.length > 0 ? wsLogs : [
        { time: '--:--:--', tag: 'INFO', tagClass: 'info', msg: 'Waiting for active scan...' },
    ];

    return (
        <div className="dashboard-layout">
            {/* Sidebar */}
            <aside className="sidebar">
                <div className="sidebar-logo">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                </div>
                <nav className="sidebar-nav">
                    <button className="sidebar-item active">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" />
                        </svg>
                    </button>
                    <button className="sidebar-item">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" />
                        </svg>
                    </button>
                    <button className="sidebar-item">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                        </svg>
                    </button>
                    <button className="sidebar-item">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                        </svg>
                    </button>
                </nav>
                <div className="sidebar-avatar">C</div>
            </aside>

            {/* Main */}
            <main className="dashboard-main">
                {/* Top Bar */}
                <header className="topbar">
                    <h1 className="topbar-title">Command Center</h1>
                    <div className="topbar-url">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                        </svg>
                        <input type="text" defaultValue="https://target-endpoint.io/scan" readOnly />
                    </div>
                    <div className="topbar-actions">
                        <button className="topbar-btn topbar-btn-primary" onClick={() => setShowModal('url')}>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="16" /><line x1="8" y1="12" x2="16" y2="12" />
                            </svg>
                            New Website Scan
                        </button>
                        <button className="topbar-btn topbar-btn-secondary" onClick={() => setShowModal('repo')}>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
                            </svg>
                            New Repo Scan
                        </button>
                    </div>
                </header>

                {/* Scan History */}
                <section className="scan-content">
                    <div className="scan-header">
                        <div>
                            <h2>Scan History</h2>
                            <p>Real-time overview of your security perimeter</p>
                        </div>
                        <div className="threads-badge">
                            <span className="dot"></span>
                            {activeCount} ACTIVE THREAD{activeCount !== 1 ? 'S' : ''}
                        </div>
                    </div>

                    <div className="scan-table-container">
                        <table className="scan-table">
                            <thead>
                                <tr>
                                    <th>TARGET URL</th>
                                    <th>TYPE</th>
                                    <th>SECURITY SCORE</th>
                                    <th>STATUS</th>
                                    <th>LAST SEEN</th>
                                    <th>ACTIONS</th>
                                </tr>
                            </thead>
                            <tbody>
                                {loading ? (
                                    <tr><td colSpan="6" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-tertiary)' }}>Loading scans...</td></tr>
                                ) : scans.length === 0 ? (
                                    <tr><td colSpan="6" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-tertiary)' }}>No scans yet. Click "New Website Scan" or "New Repo Scan" to get started.</td></tr>
                                ) : (
                                    scans.map((scan) => {
                                        const { icon, color } = getTargetIcon(scan);
                                        const statusInfo = STATUS_MAP[scan.status] || { label: scan.status?.toUpperCase(), cls: 'active' };
                                        const score = scan.risk_score != null ? Math.round(scan.risk_score) : '—';
                                        return (
                                            <tr key={scan.id} onClick={() => setSelectedScan(scan)} style={{ cursor: 'pointer' }}>
                                                <td>
                                                    <div className="target-cell">
                                                        <div className={`target-icon ${color}`}>
                                                            <ScanIcon type={icon} />
                                                        </div>
                                                        <span className="target-name">{scan.target_url}</span>
                                                    </div>
                                                </td>
                                                <td><span className="type-badge">{TYPE_LABELS[scan.scan_type] || scan.scan_type}</span></td>
                                                <td>
                                                    <div className={`score-circle ${typeof score === 'number' ? getScoreClass(score) : 'medium'}`}>
                                                        {score}
                                                    </div>
                                                </td>
                                                <td>
                                                    <span className={`status-badge ${statusInfo.cls}`}>
                                                        <span className="dot"></span>
                                                        {statusInfo.label}
                                                    </span>
                                                </td>
                                                <td><span className="last-seen">{timeAgo(scan.updated_at)}</span></td>
                                                <td>
                                                    <button className="action-btn" onClick={(e) => { e.stopPropagation(); setSelectedScan(scan); }}>
                                                        <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
                                                            <circle cx="12" cy="5" r="1.5" /><circle cx="12" cy="12" r="1.5" /><circle cx="12" cy="19" r="1.5" />
                                                        </svg>
                                                    </button>
                                                </td>
                                            </tr>
                                        );
                                    })
                                )}
                            </tbody>
                        </table>
                    </div>
                </section>

                {/* Live Logs */}
                <section className="logs-panel">
                    <div className="logs-header">
                        <div className="logs-header-left">
                            <div className="logs-dots">
                                <span></span><span></span><span></span>
                            </div>
                            <div className="logs-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                                    <line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
                                </svg>
                                LIVE SCANNING LOGS
                            </div>
                        </div>
                        <div className="logs-actions">
                            <button className="logs-action-btn" onClick={() => setWsLogs([])}>
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2" /><line x1="8" y1="12" x2="16" y2="12" />
                                </svg>
                                CLEAR
                            </button>
                            <button className="logs-action-btn">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
                                </svg>
                                EXPORT
                            </button>
                        </div>
                    </div>
                    <div className="logs-body">
                        {displayLogs.map((log, i) => (
                            <div key={i} className="log-line" style={{ animation: 'fadeIn 0.3s ease-out' }}>
                                <span className="log-time">[{log.time}]</span>
                                <span className={`log-tag ${log.tagClass}`}>[{log.tag}]</span>
                                <span className={`log-msg ${log.isError ? 'error-msg' : ''}`}>
                                    {log.msg}
                                    {log.link && <> <a href="#">{log.link}</a></>}
                                </span>
                            </div>
                        ))}
                        <div ref={logsEndRef} />
                    </div>
                </section>
            </main>

            {/* Modals */}
            {showModal && (
                <ScanModal
                    defaultTargetType={showModal}
                    onClose={() => setShowModal(null)}
                    onCreated={handleScanCreated}
                />
            )}

            {selectedScan && (
                <ScanDetail
                    scan={selectedScan}
                    onClose={() => setSelectedScan(null)}
                    onScanUpdate={handleScanUpdate}
                />
            )}
        </div>
    );
}
