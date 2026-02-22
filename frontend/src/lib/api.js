/**
 * Centralized API client for the CyberSafe backend.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/**
 * Generic fetch wrapper with error handling.
 */
async function fetchApi(path, options = {}) {
    const url = `${API_BASE}${path}`;
    const config = {
        headers: {
            "Content-Type": "application/json",
            ...options.headers,
        },
        ...options,
    };

    const res = await fetch(url, config);

    if (!res.ok) {
        let detail = `HTTP ${res.status}`;
        try {
            const body = await res.json();
            detail = body.detail || detail;
        } catch { }
        throw new Error(detail);
    }

    return res.json();
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

export async function getHealth() {
    return fetchApi("/api/health");
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

/**
 * Create a new scan.
 * @param {{ target_url: string, scan_type?: string, target_type?: string }} data
 */
export async function createScan(data) {
    return fetchApi("/api/scans", {
        method: "POST",
        body: JSON.stringify({
            target_url: data.target_url,
            scan_type: data.scan_type || "dynamic",
            target_type: data.target_type || "url",
        }),
    });
}

/**
 * List scans with optional pagination and status filter.
 */
export async function listScans({ skip = 0, limit = 20, status } = {}) {
    const params = new URLSearchParams({ skip, limit });
    if (status) params.set("status", status);
    return fetchApi(`/api/scans?${params}`);
}

/**
 * Get a single scan by ID.
 */
export async function getScan(scanId) {
    return fetchApi(`/api/scans/${scanId}`);
}

/**
 * Get vulnerability results for a scan.
 */
export async function getScanResults(scanId) {
    return fetchApi(`/api/scans/${scanId}/results`);
}

/**
 * Get the generated security report.
 */
export async function getScanReport(scanId) {
    return fetchApi(`/api/scans/${scanId}/report`);
}

/**
 * Cancel a running or queued scan.
 */
export async function cancelScan(scanId) {
    return fetchApi(`/api/scans/${scanId}/cancel`, { method: "POST" });
}

/**
 * Get Gemini AI summary for a scan.
 */
export async function getAiSummary(scanId) {
    return fetchApi(`/api/scans/${scanId}/ai-summary`);
}

/**
 * Get repo intelligence data for a scan.
 */
export async function getIntelligence(scanId) {
    return fetchApi(`/api/scans/${scanId}/intelligence`);
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

/**
 * Get WebSocket URL for real-time scan logs.
 */
export function getWsUrl(scanId) {
    const base = API_BASE.replace(/^http/, "ws");
    return `${base}/ws/scans/${scanId}`;
}

export { API_BASE };
