// PE-Sentinel Frontend v2.2
// Rich Header, Import Density, PDF Export, Dark Mode

const API_URL = 'http://localhost:5000';

let currentAnalysis = null;
let sessionId = null;
let logInterval = null;
let charts = {};

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    console.log('[DEBUG] PE-Sentinel v2.2 loaded');
    setupFileUpload();
    setupDragAndDrop();
    setupAdvancedPanel();
    testConnection();
});

// Test API connection
async function testConnection() {
    try {
        const response = await fetch(`${API_URL}/api/health`);
        const data = await response.json();
        console.log('[DEBUG] API health:', data);
        addLogEntry(`✓ Connected to backend v${data.version}`, 'success');
        
        const features = Object.entries(data.features || {})
            .filter(([k, v]) => v)
            .map(([k]) => k.replace(/_/g, ' '));
        addLogEntry(`Features: ${features.join(', ')}`, 'info');
        
        if (!data.features?.yara_scanning) {
            document.getElementById('yaraTab')?.classList.add('disabled');
        }
    } catch (error) {
        console.error('[ERROR] API connect failed:', error);
        addLogEntry('✗ Cannot connect to backend. Run: python app.py', 'danger');
    }
}

// Logging
function addLogEntry(message, type = 'info') {
    const log = document.getElementById('analysisLog');
    if (!log) return;
    
    const colors = { 'info': '#17a2b8', 'success': '#28a745', 'warning': '#ffc107', 'danger': '#dc3545' };
    const entry = document.createElement('div');
    entry.style.color = colors[type] || '#e4e6eb';
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
}

// File upload setup
function setupFileUpload() {
    const fileInput = document.getElementById('fileInput');
    if (fileInput) fileInput.addEventListener('change', handleFileSelect);
}

function setupDragAndDrop() {
    const uploadZone = document.getElementById('uploadZone');
    if (!uploadZone) return;
    
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.style.borderColor = 'var(--brand-primary)';
    });
    
    uploadZone.addEventListener('dragleave', () => {
        uploadZone.style.borderColor = 'var(--border-soft)';
    });
    
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.style.borderColor = 'var(--border-soft)';
        if (e.dataTransfer.files.length > 0) uploadFile(e.dataTransfer.files[0]);
    });
}

function setupAdvancedPanel() {
    document.querySelectorAll('.adv-tab').forEach(tab => {
        tab.addEventListener('click', function() {
            const target = this.dataset.target;
            document.querySelectorAll('.adv-tab').forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            document.querySelectorAll('.adv-panel').forEach(p => p.classList.remove('active'));
            document.getElementById(target)?.classList.add('active');
        });
    });

    document.getElementById('searchFunctionsBtn')?.addEventListener('click', searchFunctions);
    document.getElementById('functionQuery')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') searchFunctions(); });
    document.getElementById('searchStringsBtn')?.addEventListener('click', searchStrings);
    document.getElementById('stringQuery')?.addEventListener('keypress', (e) => { if (e.key === 'Enter') searchStrings(); });
    document.getElementById('runYaraBtn')?.addEventListener('click', runCustomYara);
    document.getElementById('filterSectionsBtn')?.addEventListener('click', filterSections);
    document.getElementById('extractIocsBtn')?.addEventListener('click', extractIocs);
    document.getElementById('getHexdumpBtn')?.addEventListener('click', getHexdump);
    document.getElementById('downloadPdfBtn')?.addEventListener('click', downloadPdf);
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) uploadFile(file);
}

function simulateProgress() {
    const steps = [
        'Parsing PE headers...',
        'Analyzing Rich Header...',
        'Calculating import density...',
        'Analyzing section entropy...',
        'Running YARA rules...',
        'Correlating capabilities...',
        'Mapping MITRE ATT&CK...',
        'Generating verdict...',
    ];
    
    let step = 0;
    const progressBar = document.getElementById('progressBar');
    
    logInterval = setInterval(() => {
        if (step < steps.length) {
            addLogEntry(steps[step], 'info');
            if (progressBar) progressBar.style.width = `${((step + 1) / steps.length) * 100}%`;
            step++;
        } else {
            clearInterval(logInterval);
        }
    }, 400);
}

async function uploadFile(file) {
    console.log('[DEBUG] Uploading:', file.name);
    addLogEntry(`Analyzing ${file.name}...`, 'info');
    
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['exe', 'dll', 'sys'].includes(ext)) {
        addLogEntry('Invalid file type!', 'danger');
        return alert('Only .exe, .dll, .sys allowed');
    }
    
    if (file.size > 50 * 1024 * 1024) {
        addLogEntry('File too large!', 'danger');
        return alert('Max 50 MB');
    }
    
    document.getElementById('loading').style.display = 'block';
    document.getElementById('results').style.display = 'none';
    destroyCharts();
    simulateProgress();
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('include_strings', 'true');
    formData.append('include_yara', 'true');
    formData.append('keep_file', 'true');
    
    try {
        const response = await fetch(`${API_URL}/api/upload`, {
            method: 'POST',
            body: formData,
            signal: AbortSignal.timeout(180000)
        });
        
        const data = await response.json();
        if (logInterval) clearInterval(logInterval);
        
        if (data.success) {
            addLogEntry('✓ Analysis complete!', 'success');
            currentAnalysis = data;
            sessionId = data.session_id;
            
            if (sessionId) {
                addLogEntry(`Session: ${sessionId.substring(0, 16)}...`, 'info');
                enableAdvancedPanel();
            }
            
            if (data.pdf_available) {
                document.getElementById('downloadPdfBtn').style.display = 'inline-block';
            }
            
            displayResults(data);
        } else {
            throw new Error(data.error || 'Unknown error');
        }
        
    } catch (error) {
        if (logInterval) clearInterval(logInterval);
        console.error('[ERROR]', error);
        addLogEntry(`✗ ${error.message}`, 'danger');
        alert(error.message);
    } finally {
        document.getElementById('loading').style.display = 'none';
    }
}

function enableAdvancedPanel() {
    const panel = document.getElementById('advancedPanel');
    if (panel) {
        panel.style.display = 'block';
        panel.classList.add('fade-in');
    }
}

function destroyCharts() {
    Object.values(charts).forEach(chart => { if (chart?.destroy) chart.destroy(); });
    charts = {};
}

// ============================================================
// Display Results
// ============================================================

function displayResults(data) {
    document.getElementById('results').style.display = 'block';
    
    // Metadata
    document.getElementById('filename').textContent = data.metadata.filename;
    document.getElementById('filesize').textContent = formatBytes(data.metadata.filesize);
    document.getElementById('architecture').textContent = data.metadata.architecture;
    document.getElementById('entrypoint').textContent = data.metadata.entry_point;
    document.getElementById('signed').textContent = data.metadata.is_signed ? 'Yes ✓' : 'No ✗';
    document.getElementById('timestamp').textContent = new Date(data.timestamp).toLocaleString();
    
    // Quick stats
    const quickStats = document.getElementById('quickStats');
    if (quickStats) {
        quickStats.style.display = 'block';
        document.getElementById('quickArch').textContent = data.metadata.architecture;
        document.getElementById('quickSize').textContent = formatBytes(data.metadata.filesize);
        document.getElementById('quickSigned').textContent = data.metadata.is_signed ? '✓' : '✗';
        
        // Compiler from Rich Header
        const compiler = data.rich_header?.compiler_info?.visual_studio || 'Unknown';
        document.getElementById('quickCompiler').textContent = compiler;
    }
    
    // Scores
    document.getElementById('structuralScore').textContent = data.scores.structural;
    document.getElementById('behavioralScore').textContent = data.scores.behavioral;
    document.getElementById('overallScore').textContent = data.scores.overall;
    
    const badge = document.getElementById('threatBadge');
    badge.textContent = data.scores.threat_level;
    badge.style.background = data.scores.threat_color;
    badge.style.color = 'white';
    
    // Rich Header (NEW)
    displayRichHeader(data.rich_header);
    
    // Import Density (NEW)
    displayImportDensity(data.import_analysis);
    
    // Other sections
    displaySectionTable(data.sections);
    displayThreatAttribution(data.scores);
    displayCapabilities(data.capabilities);
    displayMitreMatrix(data.mitre);
    displayVerdict(data.verdict);
    
    try {
        createSectionChart(data.sections);
        createEntropyChart(data.sections);
        createEntropyHeatmap(data.sections);
    } catch (e) {
        console.error('Chart error:', e);
    }
    
    // Populate hex section dropdown
    const hexSection = document.getElementById('hexSection');
    if (hexSection) {
        hexSection.innerHTML = '<option value="">-- Section --</option>';
        data.sections.forEach(s => {
            hexSection.innerHTML += `<option value="${s.name}">${s.name}</option>`;
        });
    }
    
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

// ============================================================
// Rich Header Display (NEW)
// ============================================================

function displayRichHeader(richHeader) {
    const card = document.getElementById('richHeaderCard');
    const content = document.getElementById('richHeaderContent');
    const badge = document.getElementById('richBadge');
    
    if (!card || !richHeader) return;
    
    card.style.display = 'block';
    
    if (!richHeader.present) {
        badge.textContent = 'Not Found';
        badge.className = 'badge bg-secondary';
        content.innerHTML = `<p class="text-muted mb-0">No Rich Header found. This binary may not be compiled with Microsoft Visual Studio, or the header was stripped.</p>`;
        return;
    }
    
    const compiler = richHeader.compiler_info?.visual_studio || 'Unknown';
    badge.textContent = compiler;
    badge.className = richHeader.is_suspicious ? 'badge bg-danger' : 'badge bg-success';
    
    let html = '<div class="row">';
    
    // Compiler Info
    html += `<div class="col-md-6">
        <h6 class="mb-3">Compiler Information</h6>
        <table class="table table-sm">
            <tr><td class="text-muted">Visual Studio</td><td><strong>${compiler}</strong></td></tr>
            <tr><td class="text-muted">Max Build</td><td>${richHeader.compiler_info?.max_build || 'N/A'}</td></tr>
            <tr><td class="text-muted">Tool Entries</td><td>${richHeader.entries_count}</td></tr>
            <tr><td class="text-muted">Valid Checksum</td><td>${richHeader.valid ? '✓ Yes' : '✗ No'}</td></tr>
            <tr><td class="text-muted">Checksum</td><td><code>${richHeader.checksum || 'N/A'}</code></td></tr>
        </table>
    </div>`;
    
    // Timestamp Analysis
    const tsAnalysis = richHeader.timestamp_analysis;
    if (tsAnalysis?.checked) {
        html += `<div class="col-md-6">
            <h6 class="mb-3">Timestamp Analysis</h6>
            <div class="import-alert ${tsAnalysis.is_anomalous ? '' : 'info'}">
                <strong>${tsAnalysis.verdict}</strong><br>
                <small>Compiler Year: ${tsAnalysis.compiler_year} | PE Year: ${tsAnalysis.pe_year}</small>
            </div>`;
        
        if (tsAnalysis.anomalies?.length > 0) {
            html += '<ul class="small text-danger mb-0">';
            tsAnalysis.anomalies.forEach(a => html += `<li>${a}</li>`);
            html += '</ul>';
        }
        html += '</div>';
    }
    
    html += '</div>';
    
    // Warnings
    if (richHeader.suspicion_reasons?.length > 0 || richHeader.warnings?.length > 0) {
        html += '<div class="mt-3"><h6>⚠️ Warnings</h6><ul class="text-danger small mb-0">';
        [...(richHeader.suspicion_reasons || []), ...(richHeader.warnings || [])].forEach(w => {
            html += `<li>${w}</li>`;
        });
        html += '</ul></div>';
    }
    
    // Tool entries (collapsible)
    if (richHeader.entries?.length > 0) {
        html += `<details class="mt-3">
            <summary class="text-muted" style="cursor:pointer;">View ${richHeader.entries.length} Tool Entries</summary>
            <table class="table table-sm mt-2" style="font-size:0.8rem;">
                <thead><tr><th>Tool</th><th>ID</th><th>Build</th><th>Count</th></tr></thead>
                <tbody>`;
        richHeader.entries.forEach(e => {
            html += `<tr><td>${e.tool_name}</td><td>0x${e.tool_id.toString(16).toUpperCase()}</td><td>${e.tool_version}</td><td>${e.use_count}</td></tr>`;
        });
        html += '</tbody></table></details>';
    }
    
    content.innerHTML = html;
}

// ============================================================
// Import Analysis Display (Informational Only)
// ============================================================

function displayImportDensity(importAnalysis) {
    const card = document.getElementById('importDensityCard');
    const content = document.getElementById('importDensityContent');
    const badge = document.getElementById('densityBadge');
    
    if (!card || !importAnalysis || importAnalysis.error) {
        if (card) card.style.display = 'none';
        return;
    }
    
    card.style.display = 'block';
    
    const density = importAnalysis.density || {};
    const ordinal = importAnalysis.ordinal || {};
    const runtime = importAnalysis.runtime || {};
    const loaders = importAnalysis.loaders || {};
    
    // Badge shows runtime type
    const runtimeDetected = runtime.detected || 'Unknown';
    const badgeColors = {
        '.NET': 'bg-purple',
        'Go': 'bg-info',
        'Native': 'bg-success',
        'Unknown': 'bg-secondary',
    };
    badge.textContent = runtimeDetected;
    badge.className = `badge ${badgeColors[runtimeDetected] || 'bg-secondary'}`;
    badge.style.background = runtimeDetected === '.NET' ? '#7c3aed' : '';
    
    let html = '<div class="row">';
    
    // Density stats
    html += `<div class="col-md-4">
        <h6 class="mb-3">Import Statistics</h6>
        <table class="table table-sm">
            <tr><td class="text-muted">Total Imports</td><td><strong>${density.total_imports || 0}</strong></td></tr>
            <tr><td class="text-muted">DLL Count</td><td>${density.dll_count || 0}</td></tr>
            <tr><td class="text-muted">Density Level</td><td><span class="badge bg-secondary">${density.level || 'N/A'}</span></td></tr>
            <tr><td class="text-muted">Pattern</td><td>${density.pattern || 'N/A'}</td></tr>
        </table>
    </div>`;
    
    // Ordinal stats
    html += `<div class="col-md-4">
        <h6 class="mb-3">Ordinal Analysis</h6>
        <table class="table table-sm">
            <tr><td class="text-muted">Ordinal Imports</td><td><strong>${ordinal.ordinal_count || 0}</strong></td></tr>
            <tr><td class="text-muted">Ordinal Ratio</td><td>${ordinal.ratio_percent || '0%'}</td></tr>
        </table>
    </div>`;
    
    // Runtime detection
    html += `<div class="col-md-4">
        <h6 class="mb-3">Runtime Detection</h6>
        <table class="table table-sm">
            <tr><td class="text-muted">Detected Runtime</td><td><strong>${runtimeDetected}</strong></td></tr>
            <tr><td class="text-muted">.NET Application</td><td>${runtime.is_dotnet ? '✓ Yes' : 'No'}</td></tr>
            <tr><td class="text-muted">Go Application</td><td>${runtime.is_go ? '✓ Yes' : 'No'}</td></tr>
            <tr><td class="text-muted">Has Loaders</td><td>${loaders.has_critical_loaders ? 'Yes' : 'No'}</td></tr>
        </table>
    </div>`;
    
    html += '</div>';
    
    // Info note
    if (runtime.is_dotnet || runtime.is_go) {
        html += `<div class="alert alert-info mt-3 mb-0" style="font-size: 0.85rem;">
            <i class="fas fa-info-circle me-2"></i>
            <strong>${runtimeDetected} Runtime Detected:</strong> 
            Low import counts are normal for ${runtimeDetected} applications as they use runtime libraries for most functionality.
        </div>`;
    } else if (density.level === 'MINIMAL' || density.level === 'LOW') {
        html += `<div class="alert alert-secondary mt-3 mb-0" style="font-size: 0.85rem;">
            <i class="fas fa-info-circle me-2"></i>
            <strong>Note:</strong> 
            This binary has a minimal import table. This could indicate a packed binary, a runtime-based application, or a specialized tool.
        </div>`;
    }
    
    // Loader functions if present
    if (loaders.loader_functions?.length > 0) {
        html += `<div class="mt-3">
            <small class="text-muted">Loader Functions: ${loaders.loader_functions.join(', ')}</small>
        </div>`;
    }
    
    content.innerHTML = html;
}

// ============================================================
// Other Display Functions
// ============================================================

function displaySectionTable(sections) {
    const tbody = document.getElementById('sectionTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    sections.forEach(s => {
        const levelColors = {
            'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107',
            'LOW': '#28a745', 'CLEAN': '#20c997'
        };
        
        const row = tbody.insertRow();
        row.innerHTML = `
            <td><strong>${s.name}</strong></td>
            <td>${s.entropy.toFixed(2)}</td>
            <td>${s.size_ratio.toFixed(2)}x</td>
            <td><code>${s.permissions}</code></td>
            <td><strong>${s.suspicion_score}</strong></td>
            <td><span class="badge" style="background:${levelColors[s.suspicion_level]}">${s.suspicion_level}</span></td>
        `;
        if (s.is_suspicious) row.style.background = 'rgba(220,53,69,0.05)';
    });
}

function displayThreatAttribution(scores) {
    const ctx = document.getElementById('attributionRadar');
    if (!ctx) return;
    
    const attr = scores.attribution || {};
    const theme = document.documentElement.getAttribute('data-theme');
    const textColor = theme === 'dark' ? '#f1f5f9' : '#1e293b';
    
    charts.attribution = new Chart(ctx.getContext('2d'), {
        type: 'radar',
        data: {
            labels: Object.keys(attr),
            datasets: [{
                label: 'Threat Profile',
                data: Object.values(attr),
                backgroundColor: 'rgba(220,53,69,0.2)',
                borderColor: '#dc3545',
                borderWidth: 2,
            }]
        },
        options: {
            responsive: true,
            scales: { r: { beginAtZero: true, max: 50, ticks: { color: textColor }, grid: { color: theme === 'dark' ? '#334155' : '#e2e8f0' } } },
            plugins: { legend: { display: false, labels: { color: textColor } } }
        }
    });
}

function displayCapabilities(capabilities) {
    const container = document.getElementById('capabilitiesContainer');
    if (!container) return;
    
    if (!capabilities?.length) {
        container.innerHTML = '<div class="alert alert-success mb-0">✓ No malicious capabilities detected</div>';
        return;
    }
    
    let html = '<div class="alert alert-danger mb-3">⚠️ Malicious capabilities detected</div>';
    capabilities.forEach(c => {
        html += `
            <div class="border rounded p-2 mb-2" style="border-left: 4px solid #dc3545 !important;">
                <div class="d-flex justify-content-between">
                    <strong>${c.description}</strong>
                    <span class="badge bg-danger">${c.score} pts</span>
                </div>
                <small class="text-muted">APIs: ${c.matched_apis?.slice(0,5).join(', ')}</small>
            </div>
        `;
    });
    container.innerHTML = html;
}

function displayMitreMatrix(mitre) {
    const container = document.getElementById('mitreMatrix');
    const badge = document.getElementById('mitreBadge');
    if (!container) return;
    
    badge.textContent = mitre.total_techniques;
    
    if (!mitre.total_techniques) {
        container.innerHTML = '<div class="alert alert-success mb-0">✓ No MITRE ATT&CK techniques detected</div>';
        return;
    }
    
    let html = '<div class="alert alert-danger mb-3">⚠️ MITRE ATT&CK techniques detected</div>';
    for (const [tactic, techniques] of Object.entries(mitre.matrix)) {
        html += `<h6 class="text-muted small">${tactic}</h6><div class="d-flex flex-wrap gap-2 mb-3">`;
        techniques.forEach(t => { html += `<span class="badge bg-danger">${t.id}: ${t.name}</span>`; });
        html += '</div>';
    }
    container.innerHTML = html;
}

function displayVerdict(verdict) {
    const container = document.getElementById('verdictContainer');
    if (!container) return;
    
    let html = verdict.is_likely_malicious
        ? '<div class="alert alert-danger"><h5>⚠️ LIKELY MALICIOUS</h5></div>'
        : '<div class="alert alert-success"><h5>✓ Likely Benign</h5></div>';
    
    if (verdict.recommendations?.length) {
        html += '<h6>Recommendations:</h6><ul>';
        verdict.recommendations.forEach(r => html += `<li>${r}</li>`);
        html += '</ul>';
    }
    
    container.innerHTML = html;
}

// ============================================================
// Charts
// ============================================================

function createSectionChart(sections) {
    const ctx = document.getElementById('sectionChart');
    if (!ctx) return;
    
    const theme = document.documentElement.getAttribute('data-theme');
    
    charts.section = new Chart(ctx.getContext('2d'), {
        type: 'pie',
        data: {
            labels: sections.map(s => s.name),
            datasets: [{ data: sections.map(s => s.virtual_size), backgroundColor: ['#4f46e5','#7c3aed','#ec4899','#f59e0b','#10b981','#06b6d4'] }]
        },
        options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: theme === 'dark' ? '#f1f5f9' : '#1e293b' } } } }
    });
}

function createEntropyChart(sections) {
    const ctx = document.getElementById('entropyChart');
    if (!ctx) return;
    
    const theme = document.documentElement.getAttribute('data-theme');
    
    charts.entropy = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: sections.map(s => s.name),
            datasets: [{
                label: 'Entropy',
                data: sections.map(s => s.entropy),
                backgroundColor: sections.map(s => s.entropy > 7.5 ? '#dc3545' : s.entropy > 6.5 ? '#ffc107' : '#28a745')
            }]
        },
        options: { 
            responsive: true, 
            scales: { 
                y: { beginAtZero: true, max: 8, ticks: { color: theme === 'dark' ? '#f1f5f9' : '#1e293b' }, grid: { color: theme === 'dark' ? '#334155' : '#e2e8f0' } },
                x: { ticks: { color: theme === 'dark' ? '#f1f5f9' : '#1e293b' }, grid: { color: theme === 'dark' ? '#334155' : '#e2e8f0' } }
            },
            plugins: { legend: { labels: { color: theme === 'dark' ? '#f1f5f9' : '#1e293b' } } }
        }
    });
}

function createEntropyHeatmap(sections) {
    const plot = document.getElementById('heatmapPlot');
    if (!plot) return;
    
    const theme = document.documentElement.getAttribute('data-theme');
    const data = [];
    sections.forEach(s => {
        if (s.segment_analysis?.entropies) {
            s.segment_analysis.entropies.forEach((e, i) => {
                data.push({ section: s.name, offset: i * 4, entropy: e });
            });
        }
    });
    
    if (!data.length) {
        plot.innerHTML = '<p class="text-center text-muted">No segment data</p>';
        return;
    }
    
    const names = [...new Set(data.map(d => d.section))];
    const z = names.map(n => data.filter(d => d.section === n).map(d => d.entropy));
    const x = data.filter(d => d.section === names[0]).map(d => d.offset);
    
    Plotly.newPlot(plot, [{
        z, x, y: names, type: 'heatmap',
        colorscale: [[0,'#28a745'],[0.5,'#ffc107'],[1,'#dc3545']]
    }], { 
        margin: { t: 30, l: 80, r: 30, b: 40 },
        paper_bgcolor: theme === 'dark' ? '#1e293b' : '#ffffff',
        plot_bgcolor: theme === 'dark' ? '#1e293b' : '#ffffff',
        font: { color: theme === 'dark' ? '#f1f5f9' : '#1e293b' }
    });
}

// ============================================================
// Advanced Search Functions
// ============================================================

async function searchFunctions() {
    if (!sessionId) return alert('Analyze a file first');

    const query = document.getElementById('functionQuery').value.trim();
    const searchType = document.getElementById('functionSearchType').value;
    const includeExports = document.getElementById('includeExports').checked;
    const resultsDiv = document.getElementById('functionResults');

    if (!query) return alert('Enter a search query');

    resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border spinner-border-sm"></div> Searching...</div>';

    try {
        const response = await fetch(`${API_URL}/api/search/functions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, query, search_type: searchType, include_exports: includeExports }),
        });

        const data = await response.json();
        if (!data.success) throw new Error(data.error);

        let html = `<div class="alert alert-info">Found ${data.total_imports} imports, ${data.total_exports} exports</div>`;

        if (data.results.imports.length > 0) {
            html += '<h6>Imports</h6><div class="table-responsive"><table class="table table-sm"><thead><tr><th>DLL</th><th>Function</th></tr></thead><tbody>';
            data.results.imports.forEach(imp => {
                const isHighRisk = isHighRiskFunction(imp.function);
                html += `<tr class="${isHighRisk ? 'table-danger' : ''}"><td><code>${imp.dll}</code></td><td><strong>${imp.function}</strong>${isHighRisk ? ' ⚠️' : ''}</td></tr>`;
            });
            html += '</tbody></table></div>';
        }

        if (data.results.exports.length > 0) {
            html += '<h6 class="mt-3">Exports</h6><div class="table-responsive"><table class="table table-sm"><thead><tr><th>Function</th><th>Ordinal</th></tr></thead><tbody>';
            data.results.exports.forEach(exp => {
                html += `<tr><td><strong>${exp.function}</strong></td><td>${exp.ordinal}</td></tr>`;
            });
            html += '</tbody></table></div>';
        }

        if (data.total_imports === 0 && data.total_exports === 0) html = '<div class="alert alert-warning">No matches found</div>';

        resultsDiv.innerHTML = html;

    } catch (error) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">${error.message}</div>`;
    }
}

function isHighRiskFunction(name) {
    const highRisk = ['VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThread', 'SetWindowsHookEx', 'GetAsyncKeyState', 'LoadLibrary', 'GetProcAddress', 'CreateProcess', 'ShellExecute', 'WinExec', 'URLDownloadToFile', 'InternetOpen', 'CryptEncrypt', 'RegSetValue', 'CreateService', 'OpenProcess'];
    return highRisk.some(hr => name.toLowerCase().includes(hr.toLowerCase()));
}

async function searchStrings() {
    if (!sessionId) return alert('Analyze a file first');

    const query = document.getElementById('stringQuery').value.trim();
    const searchType = document.getElementById('stringSearchType').value;
    const minLength = parseInt(document.getElementById('stringMinLength').value) || 4;
    const resultsDiv = document.getElementById('stringResults');

    resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border spinner-border-sm"></div> Searching...</div>';

    try {
        const response = await fetch(`${API_URL}/api/search/strings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, query, search_type: searchType, min_length: minLength, max_results: 200 }),
        });

        const data = await response.json();
        if (!data.success) throw new Error(data.error);

        let html = `<div class="alert alert-info">Found ${data.matched_count} of ${data.total_strings} strings${data.truncated ? ' (truncated)' : ''}</div>`;

        if (data.strings.length > 0) {
            html += '<div class="string-results" style="max-height: 400px; overflow-y: auto;">';
            data.strings.forEach((str, i) => {
                const isUrl = str.match(/https?:\/\//i);
                const isPath = str.match(/[A-Z]:\\/i);
                const isRegistry = str.match(/HKEY_|SOFTWARE\\/i);
                
                let badge = '';
                if (isUrl) badge = '<span class="badge bg-danger">URL</span>';
                else if (isRegistry) badge = '<span class="badge bg-warning">Registry</span>';
                else if (isPath) badge = '<span class="badge bg-info">Path</span>';
                
                html += `<div class="string-item p-2 border-bottom" style="font-family: monospace; font-size: 0.85rem;"><span class="text-muted me-2">${i + 1}.</span>${badge}<span class="ms-1">${escapeHtml(str)}</span></div>`;
            });
            html += '</div>';
        } else {
            html = '<div class="alert alert-warning">No strings found</div>';
        }

        resultsDiv.innerHTML = html;

    } catch (error) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">${error.message}</div>`;
    }
}

async function runCustomYara() {
    if (!sessionId) return alert('Analyze a file first');

    const rules = document.getElementById('yaraRules').value.trim();
    const resultsDiv = document.getElementById('yaraResults');

    if (!rules) return alert('Enter YARA rules');

    resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border spinner-border-sm"></div> Scanning...</div>';

    try {
        const response = await fetch(`${API_URL}/api/search/yara`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, rules }),
        });

        const data = await response.json();
        if (!data.success) throw new Error(data.error);

        let html = '';
        if (data.matches.length > 0) {
            html = `<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>${data.total_matches} rule(s) matched!</div>`;
            data.matches.forEach(match => {
                html += `<div class="card mb-2 border-danger"><div class="card-header bg-danger text-white"><strong>${match.rule}</strong>${match.tags.map(t => `<span class="badge bg-light text-dark ms-1">${t}</span>`).join('')}</div>
                <div class="card-body">${match.strings.length > 0 ? `<strong>Matches:</strong><table class="table table-sm mt-1"><thead><tr><th>ID</th><th>Offset</th><th>Data</th></tr></thead><tbody>${match.strings.slice(0, 20).map(s => `<tr><td><code>${s.identifier}</code></td><td><code>0x${s.offset.toString(16)}</code></td><td><code>${escapeHtml(s.data)}</code></td></tr>`).join('')}</tbody></table>` : ''}</div></div>`;
            });
        } else {
            html = '<div class="alert alert-success"><i class="fas fa-check-circle me-2"></i>No rules matched</div>';
        }

        resultsDiv.innerHTML = html;

    } catch (error) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">${error.message}</div>`;
    }
}

async function filterSections() {
    if (!sessionId) return alert('Analyze a file first');

    const minEntropy = parseFloat(document.getElementById('sectionMinEntropy').value) || 0;
    const permissions = document.getElementById('sectionPermissions').value.trim();
    const suspiciousOnly = document.getElementById('sectionSuspiciousOnly').checked;
    const resultsDiv = document.getElementById('sectionResults');

    resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border spinner-border-sm"></div> Filtering...</div>';

    try {
        const filter = {};
        if (minEntropy > 0) filter.min_entropy = minEntropy;
        if (permissions) filter.permissions = permissions;
        if (suspiciousOnly) filter.suspicious_only = true;

        const response = await fetch(`${API_URL}/api/search/sections`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, filter }),
        });

        const data = await response.json();
        if (!data.success) throw new Error(data.error);

        let html = `<div class="alert alert-info">Showing ${data.filtered_count} of ${data.total_sections} sections</div>`;

        if (data.sections.length > 0) {
            html += '<div class="table-responsive"><table class="table table-sm"><thead><tr><th>Name</th><th>Entropy</th><th>Ratio</th><th>Perms</th><th>Score</th><th>Level</th></tr></thead><tbody>';
            data.sections.forEach(s => {
                const levelClass = s.suspicion_level === 'CRITICAL' ? 'table-danger' : s.suspicion_level === 'HIGH' ? 'table-warning' : '';
                html += `<tr class="${levelClass}"><td><strong>${s.name}</strong></td><td>${s.entropy.toFixed(2)}</td><td>${s.size_ratio.toFixed(2)}x</td><td><code>${s.permissions}</code></td><td>${s.suspicion_score}</td><td>${s.suspicion_level}</td></tr>`;
            });
            html += '</tbody></table></div>';
        } else {
            html = '<div class="alert alert-warning">No sections match the filter</div>';
        }

        resultsDiv.innerHTML = html;

    } catch (error) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">${error.message}</div>`;
    }
}

async function extractIocs() {
    if (!sessionId) return alert('Analyze a file first');

    const resultsDiv = document.getElementById('iocResults');
    resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border spinner-border-sm"></div> Extracting...</div>';

    try {
        const response = await fetch(`${API_URL}/api/extract/iocs`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, types: ['urls', 'ips', 'domains', 'files', 'registry'] }),
        });

        const data = await response.json();
        if (!data.success) throw new Error(data.error);

        let html = `<div class="alert alert-info">Extracted ${data.total} IOCs from ${data.filename}</div>`;

        const iocTypes = {
            urls: { icon: '🔗', label: 'URLs', color: 'danger' },
            ips: { icon: '🌐', label: 'IP Addresses', color: 'warning' },
            domains: { icon: '🏠', label: 'Domains', color: 'info' },
            files: { icon: '📁', label: 'File Paths', color: 'secondary' },
            registry: { icon: '🔧', label: 'Registry Keys', color: 'dark' },
        };

        for (const [type, config] of Object.entries(iocTypes)) {
            const items = data.iocs[type] || [];
            if (items.length > 0) {
                html += `<div class="mb-3"><h6>${config.icon} ${config.label} (${items.length})</h6><div class="d-flex flex-wrap gap-1">${items.slice(0, 20).map(item => `<code class="badge bg-${config.color}">${escapeHtml(item.substring(0, 60))}${item.length > 60 ? '...' : ''}</code>`).join('')}${items.length > 20 ? `<span class="text-muted">+${items.length - 20} more</span>` : ''}</div></div>`;
            }
        }

        html += `<div class="mt-3"><button class="btn btn-sm btn-outline-primary" onclick="downloadIocs()"><i class="fas fa-download me-1"></i>Export IOCs (JSON)</button></div>`;

        resultsDiv.innerHTML = html;
        window.currentIocs = data.iocs;

    } catch (error) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">${error.message}</div>`;
    }
}

function downloadIocs() {
    if (!window.currentIocs) return;
    const blob = new Blob([JSON.stringify(window.currentIocs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `iocs_${currentAnalysis?.metadata?.filename || 'unknown'}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

async function getHexdump() {
    if (!sessionId) return alert('Analyze a file first');

    const section = document.getElementById('hexSection').value.trim();
    const offset = parseInt(document.getElementById('hexOffset').value) || 0;
    const length = parseInt(document.getElementById('hexLength').value) || 256;
    const resultsDiv = document.getElementById('hexResults');

    resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border spinner-border-sm"></div> Loading...</div>';

    try {
        const body = { session_id: sessionId, length };
        if (section) body.section = section;
        else body.offset = offset;

        const response = await fetch(`${API_URL}/api/hexdump`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        const data = await response.json();
        if (!data.success) throw new Error(data.error);

        let html = `<div class="alert alert-info">Offset: 0x${data.offset.toString(16)} | Length: ${data.length} bytes</div>`;
        html += '<div class="hexdump" style="font-family: monospace; font-size: 0.85rem; background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 8px; overflow-x: auto;">';
        
        data.lines.forEach(line => {
            html += `<div><span style="color: #60a5fa;">${line.offset}</span>  <span style="color: #fbbf24;">${line.hex.padEnd(48)}</span>  <span style="color: #34d399;">${line.ascii}</span></div>`;
        });
        
        html += '</div>';
        resultsDiv.innerHTML = html;

    } catch (error) {
        resultsDiv.innerHTML = `<div class="alert alert-danger">${error.message}</div>`;
    }
}

// ============================================================
// PDF Export (NEW)
// ============================================================

async function downloadPdf() {
    if (!sessionId) return alert('Analyze a file first');
    
    addLogEntry('Generating PDF report...', 'info');
    
    try {
        const response = await fetch(`${API_URL}/api/export/pdf/${sessionId}`);
        
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'PDF generation failed');
        }
        
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pe-sentinel-report-${currentAnalysis?.metadata?.filename || 'unknown'}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        
        addLogEntry('✓ PDF downloaded', 'success');
        
    } catch (error) {
        addLogEntry(`✗ PDF export failed: ${error.message}`, 'danger');
        alert(`PDF export failed: ${error.message}`);
    }
}

// ============================================================
// Utilities
// ============================================================

function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}