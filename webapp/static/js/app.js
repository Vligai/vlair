// SecOps Helper Dashboard JavaScript

// Global state
let currentResults = {};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadDashboardStats();
    // Load stats every 30 seconds
    setInterval(loadDashboardStats, 30000);
});

// Load dashboard statistics
async function loadDashboardStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();

        document.getElementById('total-analyses').textContent = stats.total_analyses || 0;
        document.getElementById('iocs-extracted').textContent = stats.iocs_extracted || 0;
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Show/hide loading spinner
function showLoading(show) {
    document.getElementById('loading').style.display = show ? 'block' : 'none';
}

// Show error message
function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    setTimeout(() => {
        errorDiv.style.display = 'none';
    }, 5000);
}

// Tool tab switching
function showTool(toolName) {
    // Hide all tool panels
    document.querySelectorAll('.tool-panel').forEach(panel => {
        panel.classList.remove('active');
    });

    // Remove active class from all tabs
    document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });

    // Show selected tool panel
    document.getElementById('tool-' + toolName).classList.add('active');

    // Mark tab as active
    event.target.classList.add('active');
}

// IOC Extractor Functions
async function extractIOCs() {
    const text = document.getElementById('ioc-text').value;
    const fileInput = document.getElementById('ioc-file');
    const defang = document.getElementById('ioc-defang').checked;
    const excludePrivate = document.getElementById('ioc-exclude-private').checked;

    // Get selected IOC types
    const types = Array.from(document.querySelectorAll('.ioc-type:checked')).map(cb => cb.value);

    if (!text && !fileInput.files.length) {
        showError('Please provide text or upload a file');
        return;
    }

    showLoading(true);

    try {
        let requestData = {
            text: text,
            types: types.length ? types : ['all'],
            defang: defang,
            exclude_private_ips: excludePrivate
        };

        const response = await fetch('/api/ioc/extract', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        });

        if (!response.ok) {
            throw new Error('Extraction failed');
        }

        const data = await response.json();
        currentResults.ioc = data;
        displayIOCResults(data);

    } catch (error) {
        showError('Error extracting IOCs: ' + error.message);
    } finally {
        showLoading(false);
    }
}

function displayIOCResults(data) {
    const resultsDiv = document.getElementById('ioc-results');
    const statsDiv = document.getElementById('ioc-stats');
    const contentDiv = document.getElementById('ioc-content');

    // Show results section
    resultsDiv.style.display = 'block';

    // Display statistics
    const stats = data.statistics;
    statsDiv.innerHTML = `
        <div class="stat-card">
            <span class="stat-card-value">${stats.total_iocs}</span>
            <span class="stat-card-label">Total IOCs</span>
        </div>
        <div class="stat-card ${stats.ips > 0 ? 'warning' : ''}">
            <span class="stat-card-value">${stats.ips}</span>
            <span class="stat-card-label">IP Addresses</span>
        </div>
        <div class="stat-card ${stats.domains > 0 ? 'warning' : ''}">
            <span class="stat-card-value">${stats.domains}</span>
            <span class="stat-card-label">Domains</span>
        </div>
        <div class="stat-card ${stats.urls > 0 ? 'danger' : ''}">
            <span class="stat-card-value">${stats.urls}</span>
            <span class="stat-card-label">URLs</span>
        </div>
        <div class="stat-card ${stats.hashes > 0 ? 'success' : ''}">
            <span class="stat-card-value">${stats.hashes}</span>
            <span class="stat-card-label">File Hashes</span>
        </div>
        <div class="stat-card ${stats.cves > 0 ? 'danger' : ''}">
            <span class="stat-card-value">${stats.cves}</span>
            <span class="stat-card-label">CVEs</span>
        </div>
    `;

    // Display IOC lists
    const results = data.results;
    let html = '';

    if (results.ips && results.ips.length) {
        html += `<div class="result-item">
            <div class="result-header">IP Addresses (${results.ips.length})</div>
            <ul class="ioc-list">
                ${results.ips.map(ip => `<li>${escapeHtml(ip)}</li>`).join('')}
            </ul>
        </div>`;
    }

    if (results.domains && results.domains.length) {
        html += `<div class="result-item">
            <div class="result-header">Domains (${results.domains.length})</div>
            <ul class="ioc-list">
                ${results.domains.map(d => `<li>${escapeHtml(d)}</li>`).join('')}
            </ul>
        </div>`;
    }

    if (results.urls && results.urls.length) {
        html += `<div class="result-item">
            <div class="result-header">URLs (${results.urls.length})</div>
            <ul class="ioc-list">
                ${results.urls.map(u => `<li>${escapeHtml(u)}</li>`).join('')}
            </ul>
        </div>`;
    }

    if (results.emails && results.emails.length) {
        html += `<div class="result-item">
            <div class="result-header">Email Addresses (${results.emails.length})</div>
            <ul class="ioc-list">
                ${results.emails.map(e => `<li>${escapeHtml(e)}</li>`).join('')}
            </ul>
        </div>`;
    }

    if (results.hashes) {
        for (const [hashType, hashes] of Object.entries(results.hashes)) {
            if (hashes.length) {
                html += `<div class="result-item">
                    <div class="result-header">${hashType.toUpperCase()} Hashes (${hashes.length})</div>
                    <ul class="ioc-list">
                        ${hashes.map(h => `<li>${escapeHtml(h)}</li>`).join('')}
                    </ul>
                </div>`;
            }
        }
    }

    if (results.cves && results.cves.length) {
        html += `<div class="result-item">
            <div class="result-header">CVE Identifiers (${results.cves.length})</div>
            <ul class="ioc-list">
                ${results.cves.map(c => `<li>${escapeHtml(c)}</li>`).join('')}
            </ul>
        </div>`;
    }

    contentDiv.innerHTML = html || '<p>No IOCs found in the provided text.</p>';
}

// Hash Lookup Functions
async function lookupHashes() {
    const hashInput = document.getElementById('hash-input').value;
    const hashes = hashInput.split('\n').filter(h => h.trim()).map(h => h.trim());

    if (!hashes.length) {
        showError('Please enter at least one hash');
        return;
    }

    showLoading(true);

    try {
        const response = await fetch('/api/hash/lookup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ hashes: hashes })
        });

        if (!response.ok) {
            throw new Error('Hash lookup failed');
        }

        const data = await response.json();
        currentResults.hash = data;
        displayHashResults(data);

    } catch (error) {
        showError('Error looking up hashes: ' + error.message);
    } finally {
        showLoading(false);
    }
}

function displayHashResults(data) {
    const resultsDiv = document.getElementById('hash-results');
    const statsDiv = document.getElementById('hash-stats');
    const contentDiv = document.getElementById('hash-content');

    resultsDiv.style.display = 'block';

    // Display statistics
    const verdicts = data.statistics.verdicts;
    statsDiv.innerHTML = `
        <div class="stat-card">
            <span class="stat-card-value">${data.statistics.total_hashes}</span>
            <span class="stat-card-label">Total Hashes</span>
        </div>
        <div class="stat-card danger">
            <span class="stat-card-value">${verdicts.malicious || 0}</span>
            <span class="stat-card-label">Malicious</span>
        </div>
        <div class="stat-card warning">
            <span class="stat-card-value">${verdicts.suspicious || 0}</span>
            <span class="stat-card-label">Suspicious</span>
        </div>
        <div class="stat-card success">
            <span class="stat-card-value">${verdicts.clean || 0}</span>
            <span class="stat-card-label">Clean</span>
        </div>
        <div class="stat-card">
            <span class="stat-card-value">${verdicts.unknown || 0}</span>
            <span class="stat-card-label">Unknown</span>
        </div>
    `;

    // Display individual results
    let html = '';
    for (const result of data.results) {
        const verdictClass = result.verdict || 'unknown';
        html += `<div class="result-item ${verdictClass}">
            <div class="result-header">${escapeHtml(result.hash)}</div>
            <div class="result-details">
                <strong>Verdict:</strong> ${escapeHtml(result.verdict || 'Unknown')}<br>
                <strong>Risk Score:</strong> ${result.risk_score || 'N/A'}<br>
                ${result.detections ? `<strong>Detections:</strong> ${result.detections}<br>` : ''}
                ${result.file_name ? `<strong>File Name:</strong> ${escapeHtml(result.file_name)}<br>` : ''}
            </div>
        </div>`;
    }

    contentDiv.innerHTML = html || '<p>No results found.</p>';
}

// Intelligence Analysis Functions
async function analyzeIntelligence() {
    const targetInput = document.getElementById('intel-input').value;
    const targets = targetInput.split('\n').filter(t => t.trim()).map(t => t.trim());

    if (!targets.length) {
        showError('Please enter at least one domain or IP address');
        return;
    }

    showLoading(true);

    try {
        const response = await fetch('/api/intel/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ targets: targets })
        });

        if (!response.ok) {
            throw new Error('Intelligence analysis failed');
        }

        const data = await response.json();
        currentResults.intel = data;
        displayIntelResults(data);

    } catch (error) {
        showError('Error analyzing targets: ' + error.message);
    } finally {
        showLoading(false);
    }
}

function displayIntelResults(data) {
    const resultsDiv = document.getElementById('intel-results');
    const statsDiv = document.getElementById('intel-stats');
    const contentDiv = document.getElementById('intel-content');

    resultsDiv.style.display = 'block';

    // Display statistics
    const riskLevels = data.statistics.risk_levels;
    statsDiv.innerHTML = `
        <div class="stat-card">
            <span class="stat-card-value">${data.statistics.total_targets}</span>
            <span class="stat-card-label">Total Analyzed</span>
        </div>
        <div class="stat-card danger">
            <span class="stat-card-value">${riskLevels.critical || 0}</span>
            <span class="stat-card-label">Critical</span>
        </div>
        <div class="stat-card danger">
            <span class="stat-card-value">${riskLevels.high || 0}</span>
            <span class="stat-card-label">High Risk</span>
        </div>
        <div class="stat-card warning">
            <span class="stat-card-value">${riskLevels.medium || 0}</span>
            <span class="stat-card-label">Medium Risk</span>
        </div>
        <div class="stat-card success">
            <span class="stat-card-value">${riskLevels.low || 0}</span>
            <span class="stat-card-label">Low Risk</span>
        </div>
    `;

    // Display results
    let html = '';
    for (const result of data.results) {
        const classification = result.classification || 'unknown';
        html += `<div class="result-item ${classification === 'critical' || classification === 'high' ? 'malicious' : classification === 'medium' ? 'suspicious' : 'clean'}">
            <div class="result-header">${escapeHtml(result.target)}</div>
            <div class="result-details">
                <strong>Type:</strong> ${escapeHtml(result.type || 'Unknown')}<br>
                <strong>Risk Score:</strong> ${result.risk_score || 'N/A'}/100<br>
                <strong>Classification:</strong> ${escapeHtml(classification)}<br>
                ${result.dns_resolution ? `<strong>Resolved To:</strong> ${escapeHtml(result.dns_resolution)}<br>` : ''}
                ${result.country ? `<strong>Country:</strong> ${escapeHtml(result.country)}<br>` : ''}
            </div>
        </div>`;
    }

    contentDiv.innerHTML = html || '<p>No results found.</p>';
}

// Log Analysis Functions
async function analyzeLogs() {
    const fileInput = document.getElementById('log-file');
    const logType = document.getElementById('log-type').value;

    if (!fileInput.files.length) {
        showError('Please upload a log file');
        return;
    }

    showLoading(true);

    try {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('log_type', logType);

        const response = await fetch('/api/log/analyze', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error('Log analysis failed');
        }

        const data = await response.json();
        currentResults.log = data;
        displayLogResults(data);

    } catch (error) {
        showError('Error analyzing logs: ' + error.message);
    } finally {
        showLoading(false);
    }
}

function displayLogResults(data) {
    const resultsDiv = document.getElementById('log-results');
    const statsDiv = document.getElementById('log-stats');
    const alertsDiv = document.getElementById('log-alerts');
    const contentDiv = document.getElementById('log-content');

    resultsDiv.style.display = 'block';

    // Display statistics
    const stats = data.statistics || {};
    statsDiv.innerHTML = `
        <div class="stat-card">
            <span class="stat-card-value">${stats.total_entries || 0}</span>
            <span class="stat-card-label">Total Entries</span>
        </div>
        <div class="stat-card danger">
            <span class="stat-card-value">${stats.total_alerts || 0}</span>
            <span class="stat-card-label">Total Alerts</span>
        </div>
        <div class="stat-card warning">
            <span class="stat-card-value">${stats.unique_ips || 0}</span>
            <span class="stat-card-label">Unique IPs</span>
        </div>
    `;

    // Display alerts
    if (data.alerts && data.alerts.length) {
        let alertsHtml = '<h4>Security Alerts</h4>';
        for (const alert of data.alerts) {
            alertsHtml += `<div class="alert ${alert.severity || 'medium'}">
                <div class="alert-title">${escapeHtml(alert.type || 'Alert')}</div>
                <div class="alert-details">
                    ${alert.description ? escapeHtml(alert.description) + '<br>' : ''}
                    ${alert.source_ip ? `<strong>Source IP:</strong> ${escapeHtml(alert.source_ip)}<br>` : ''}
                    ${alert.path ? `<strong>Path:</strong> ${escapeHtml(alert.path)}<br>` : ''}
                </div>
            </div>`;
        }
        alertsDiv.innerHTML = alertsHtml;
    } else {
        alertsDiv.innerHTML = '<p>No alerts detected.</p>';
    }

    // Display top IPs and paths
    let html = '';
    if (data.top_ips && data.top_ips.length) {
        html += '<div class="result-item"><div class="result-header">Top Source IPs</div><ul class="ioc-list">';
        for (const [ip, count] of data.top_ips) {
            html += `<li>${escapeHtml(ip)} (${count} requests)</li>`;
        }
        html += '</ul></div>';
    }

    if (data.top_paths && data.top_paths.length) {
        html += '<div class="result-item"><div class="result-header">Top Requested Paths</div><ul class="ioc-list">';
        for (const [path, count] of data.top_paths) {
            html += `<li>${escapeHtml(path)} (${count} requests)</li>`;
        }
        html += '</ul></div>';
    }

    contentDiv.innerHTML = html || '<p>No additional data available.</p>';
}

// Email Parser Functions
async function parseEmail() {
    const fileInput = document.getElementById('eml-file');
    const useVT = document.getElementById('eml-virustotal').checked;

    if (!fileInput.files.length) {
        showError('Please upload an .eml file');
        return;
    }

    showLoading(true);

    try {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('use_virustotal', useVT);

        const response = await fetch('/api/eml/parse', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error('Email parsing failed');
        }

        const data = await response.json();
        currentResults.eml = data;
        displayEmailResults(data);

    } catch (error) {
        showError('Error parsing email: ' + error.message);
    } finally {
        showLoading(false);
    }
}

function displayEmailResults(data) {
    const resultsDiv = document.getElementById('eml-results');
    const contentDiv = document.getElementById('eml-content');

    resultsDiv.style.display = 'block';

    const results = data.results || {};
    let html = '';

    // Email headers
    if (results.headers) {
        html += `<div class="result-item">
            <div class="result-header">Email Headers</div>
            <div class="result-details">
                <strong>From:</strong> ${escapeHtml(results.headers.from || 'N/A')}<br>
                <strong>To:</strong> ${escapeHtml(results.headers.to || 'N/A')}<br>
                <strong>Subject:</strong> ${escapeHtml(results.headers.subject || 'N/A')}<br>
                <strong>Date:</strong> ${escapeHtml(results.headers.date || 'N/A')}<br>
            </div>
        </div>`;
    }

    // Attachments
    if (results.attachments && results.attachments.length) {
        html += `<div class="result-item warning">
            <div class="result-header">Attachments (${results.attachments.length})</div>
            <ul class="ioc-list">`;
        for (const att of results.attachments) {
            html += `<li>${escapeHtml(att.filename || 'Unknown')} (${att.size || 'N/A'} bytes)`;
            if (att.hash) html += `<br>Hash: ${escapeHtml(att.hash)}`;
            html += `</li>`;
        }
        html += `</ul></div>`;
    }

    // Authentication
    if (results.authentication) {
        html += `<div class="result-item">
            <div class="result-header">Email Authentication</div>
            <div class="result-details">
                <strong>SPF:</strong> ${escapeHtml(results.authentication.spf || 'N/A')}<br>
                <strong>DKIM:</strong> ${escapeHtml(results.authentication.dkim || 'N/A')}<br>
                <strong>DMARC:</strong> ${escapeHtml(results.authentication.dmarc || 'N/A')}<br>
            </div>
        </div>`;
    }

    contentDiv.innerHTML = html || '<p>No email data available.</p>';
}

// Download Results
function downloadResults(toolType, format) {
    if (!currentResults[toolType]) {
        showError('No results to download');
        return;
    }

    let content, filename, mimeType;

    if (format === 'json') {
        content = JSON.stringify(currentResults[toolType], null, 2);
        filename = `secops-${toolType}-results.json`;
        mimeType = 'application/json';
    } else if (format === 'stix' && currentResults[toolType].stix) {
        content = JSON.stringify(currentResults[toolType].stix, null, 2);
        filename = `secops-${toolType}-indicators.stix.json`;
        mimeType = 'application/json';
    } else if (format === 'csv') {
        // Simple CSV conversion for hash results
        content = convertToCSV(currentResults[toolType].results);
        filename = `secops-${toolType}-results.csv`;
        mimeType = 'text/csv';
    } else {
        showError('Format not supported');
        return;
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Helper: Convert to CSV
function convertToCSV(data) {
    if (!data || !data.length) return '';

    const headers = Object.keys(data[0]);
    const rows = data.map(item =>
        headers.map(header => JSON.stringify(item[header] || '')).join(',')
    );

    return [headers.join(','), ...rows].join('\n');
}

// Helper: Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
