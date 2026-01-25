// API Configuration
const API_URL = 'http://localhost:5000';

// Global variables
let currentAnalysis = null;
let logInterval = null;

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    console.log('[DEBUG] Page loaded');
    setupFileUpload();
    setupDragAndDrop();
    testConnection();
});

// Test API connection
async function testConnection() {
    try {
        const response = await fetch(`${API_URL}/api/health`);
        const data = await response.json();
        console.log('[DEBUG] API health check:', data);
        addLogEntry('✓ Connected to backend server', 'success');
    } catch (error) {
        console.error('[ERROR] Cannot connect to API:', error);
        addLogEntry('✗ Cannot connect to backend. Make sure it is running on port 5000.', 'danger');
    }
}

// Add entry to analysis log
function addLogEntry(message, type = 'info') {
    const log = document.getElementById('analysisLog');
    if (!log) return;
    
    const colors = {
        'info': '#17a2b8',
        'success': '#28a745',
        'warning': '#ffc107',
        'danger': '#dc3545',
    };
    
    const entry = document.createElement('div');
    entry.style.color = colors[type] || '#e4e6eb';
    entry.style.marginBottom = '0.25rem';
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
}

// Setup file upload
function setupFileUpload() {
    const fileInput = document.getElementById('fileInput');
    fileInput.addEventListener('change', handleFileSelect);
}

// Setup drag and drop
function setupDragAndDrop() {
    const uploadZone = document.getElementById('uploadZone');
    
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });
    
    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });
    
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            uploadFile(files[0]);
        }
    });
}

// Handle file selection
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        console.log('[DEBUG] File selected:', file.name, file.size);
        uploadFile(file);
    }
}

// Simulate analysis progress
function simulateProgress() {
    const steps = [
        'Parsing PE headers...',
        'Analyzing section entropy...',
        'Detecting segment anomalies...',
        'Extracting IAT information...',
        'Running behavioral analysis...',
        'Correlating capabilities...',
        'Mapping MITRE ATT&CK techniques...',
        'Generating threat verdict...',
    ];
    
    let step = 0;
    logInterval = setInterval(() => {
        if (step < steps.length) {
            addLogEntry(steps[step], 'info');
            step++;
        } else {
            clearInterval(logInterval);
        }
    }, 800);
}

// Upload and analyze file
async function uploadFile(file) {
    console.log('[DEBUG] Starting upload:', file.name);
    addLogEntry(`Starting analysis of ${file.name}`, 'info');
    
    // Validate file
    const validExtensions = ['exe', 'dll', 'sys'];
    const extension = file.name.split('.').pop().toLowerCase();
    
    if (!validExtensions.includes(extension)) {
        addLogEntry('Invalid file type!', 'danger');
        alert('Invalid file type. Please upload .exe, .dll, or .sys files only.');
        return;
    }
    
    if (file.size > 50 * 1024 * 1024) {
        addLogEntry('File too large!', 'danger');
        alert('File too large. Maximum size is 50 MB.');
        return;
    }
    
    // Show loading
    document.getElementById('loading').style.display = 'block';
    document.getElementById('results').style.display = 'none';
    
    // Simulate progress
    simulateProgress();
    
    // Create form data
    const formData = new FormData();
    formData.append('file', file);
    
    console.log('[DEBUG] Sending request to:', `${API_URL}/api/upload`);
    
    try {
        const response = await fetch(`${API_URL}/api/upload`, {
            method: 'POST',
            body: formData,
            signal: AbortSignal.timeout(120000)
        });
        
        console.log('[DEBUG] Response status:', response.status);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('[ERROR] Server error:', errorText);
            throw new Error(`Server returned ${response.status}: ${errorText}`);
        }
        
        const data = await response.json();
        console.log('[DEBUG] Response data:', data);
        
        if (logInterval) clearInterval(logInterval);
        
        if (data.success) {
            addLogEntry('✓ Analysis complete!', 'success');
            currentAnalysis = data;
            displayResults(data);
        } else {
            addLogEntry('✗ Analysis failed: ' + data.error, 'danger');
            console.error('[ERROR] Analysis failed:', data);
            alert('Analysis failed: ' + (data.error || 'Unknown error'));
            if (data.traceback) {
                console.error('Traceback:', data.traceback);
            }
        }
        
    } catch (error) {
        if (logInterval) clearInterval(logInterval);
        console.error('[ERROR] Upload failed:', error);
        
        let errorMessage = 'Upload failed: ' + error.message;
        
        if (error.name === 'AbortError') {
            errorMessage = 'Request timeout. File analysis took too long.';
        } else if (error.message.includes('NetworkError') || error.message.includes('Failed to fetch')) {
            errorMessage = 'Cannot connect to server. Make sure the backend is running.';
        }
        
        addLogEntry('✗ ' + errorMessage, 'danger');
        alert(errorMessage);
    } finally {
        document.getElementById('loading').style.display = 'none';
    }
}

// Display results
function displayResults(data) {
    console.log('[DEBUG] Displaying results');
    
    // Show results section
    document.getElementById('results').style.display = 'block';
    
    // File metadata
    document.getElementById('filename').textContent = data.metadata.filename;
    document.getElementById('filesize').textContent = formatBytes(data.metadata.filesize);
    document.getElementById('architecture').textContent = data.metadata.architecture;
    document.getElementById('entrypoint').textContent = data.metadata.entry_point;
    document.getElementById('signed').textContent = data.metadata.is_signed ? 'Yes ✓' : 'No ✗';
    document.getElementById('timestamp').textContent = new Date(data.timestamp).toLocaleString();
    
    // Threat scores
    document.getElementById('structuralScore').textContent = data.scores.structural;
    document.getElementById('behavioralScore').textContent = data.scores.behavioral;
    document.getElementById('overallScore').textContent = data.scores.overall;
    
    const threatBadge = document.getElementById('threatBadge');
    threatBadge.textContent = data.scores.threat_level;
    threatBadge.style.background = data.scores.threat_color;
    threatBadge.style.color = 'white';
    
    // Section analysis table
    displaySectionTable(data.sections);
    
    // Charts
    try {
        createSectionChart(data.sections);
        createEntropyChart(data.sections);
        createEntropyHeatmap(data.sections);
    } catch (error) {
        console.error('[ERROR] Chart creation failed:', error);
    }
    
    // NEW: Attribution & Breakdown
    displayThreatAttribution(data.scores);
    displayScoreBreakdown(data);
    displayBinaryDNA(data);
    displayMitreMatrix(data.mitre);
    
    // Capabilities
    displayCapabilities(data.capabilities);
    
    // Verdict
    displayVerdict(data.verdict);
    
    // Scroll to results
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}
// Display threat attribution radar chart
function displayThreatAttribution(scores) {
    const attribution = scores.attribution || {};
    const primaryDriver = scores.primary_driver || 'Unknown';
    
    // Create radar chart
    const ctx = document.getElementById('attributionRadar');
    if (!ctx) return;
    
    new Chart(ctx.getContext('2d'), {
        type: 'radar',
        data: {
            labels: ['Capabilities', 'Stealth', 'Integrity', 'Intent'],
            datasets: [{
                label: 'Threat Profile',
                data: [
                    attribution.Capabilities || 0,
                    attribution.Stealth || 0,
                    attribution.Integrity || 0,
                    attribution.Intent || 0
                ],
                backgroundColor: 'rgba(220, 53, 69, 0.2)',
                borderColor: '#dc3545',
                borderWidth: 2,
                pointBackgroundColor: '#dc3545',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: '#dc3545'
            }]
        },
        options: {
            responsive: true,
            scales: {
                r: {
                    beginAtZero: true,
                    max: 50,
                    ticks: {
                        color: '#e4e6eb',
                        stepSize: 10
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    pointLabels: {
                        color: '#e4e6eb',
                        font: {
                            size: 14,
                            weight: 'bold'
                        }
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#e4e6eb'
                    }
                },
                title: {
                    display: true,
                    text: 'Threat Attribution Breakdown',
                    color: '#e4e6eb',
                    font: {
                        size: 16
                    }
                }
            }
        }
    });
    
    // Display breakdown text
    const breakdownDiv = document.getElementById('attributionBreakdown');
    breakdownDiv.innerHTML = `
        <h5 style="color: #e4e6eb; margin-bottom: 1rem;">Primary Threat Driver</h5>
        <div class="alert alert-warning">
            <h4><i class="fas fa-exclamation-triangle"></i> ${primaryDriver}</h4>
            <p>This is the dominant risk factor contributing to the threat score.</p>
        </div>
        
        <h6 style="color: #e4e6eb; margin-top: 1.5rem;">Pillar Breakdown:</h6>
        <ul class="list-group">
            <li class="list-group-item bg-dark text-light">
                <strong>Capabilities:</strong> ${attribution.Capabilities || 0}/50
                <div class="progress mt-2" style="height: 20px;">
                    <div class="progress-bar bg-danger" style="width: ${(attribution.Capabilities || 0) * 2}%"></div>
                </div>
                <small>Malicious API usage patterns</small>
            </li>
            <li class="list-group-item bg-dark text-light">
                <strong>Stealth:</strong> ${attribution.Stealth || 0}/40
                <div class="progress mt-2" style="height: 20px;">
                    <div class="progress-bar bg-warning" style="width: ${(attribution.Stealth || 0) * 2.5}%"></div>
                </div>
                <small>Obfuscation & packing techniques</small>
            </li>
            <li class="list-group-item bg-dark text-light">
                <strong>Integrity:</strong> ${attribution.Integrity || 0}/40
                <div class="progress mt-2" style="height: 20px;">
                    <div class="progress-bar bg-info" style="width: ${(attribution.Integrity || 0) * 2.5}%"></div>
                </div>
                <small>Trust signals (signature, metadata)</small>
            </li>
            <li class="list-group-item bg-dark text-light">
                <strong>Intent:</strong> ${attribution.Intent || 0}/30
                <div class="progress mt-2" style="height: 20px;">
                    <div class="progress-bar bg-secondary" style="width: ${(attribution.Intent || 0) * 3.33}%"></div>
                </div>
                <small>Behavioral contradictions</small>
            </li>
        </ul>
    `;
}

// Display score breakdown
function displayScoreBreakdown(data) {
    const breakdownDiv = document.getElementById('scoreBreakdown');
    
    const structural = data.scores.structural;
    const behavioral = data.scores.behavioral;
    const overall = data.scores.overall;
    const hasSig = data.features.trust_signals.has_signature;
    const hasBulk = data.features.trust_signals.has_bulk;
    
    let formula = '';
    let explanation = '';
    
    if (hasSig && hasBulk) {
        formula = `(${structural} × 0.3) + (${behavioral} × 0.7) = ${overall}`;
        explanation = '<li><strong>Signed + Metadata:</strong> 30% structural, 70% behavioral</li>';
    } else if (hasSig) {
        formula = `(${structural} × 0.4) + (${behavioral} × 0.6) = ${overall}`;
        explanation = '<li><strong>Signed only:</strong> 40% structural, 60% behavioral</li>';
    } else {
        formula = `max(${structural}, ${behavioral}) = ${overall}`;
        explanation = '<li><strong>Unsigned:</strong> Take worst-case (max score)</li>';
    }
    
    breakdownDiv.innerHTML = `
        <div class="row">
            <div class="col-md-6">
                <h5 style="color: #e4e6eb;">Calculation Formula</h5>
                <div class="alert alert-info">
                    <code style="font-size: 1.1rem;">${formula}</code>
                </div>
                
                <h6 style="color: #e4e6eb; margin-top: 1rem;">Weighting Strategy:</h6>
                <ul style="color: #b0b3b8;">
                    ${explanation}
                    <li>Trust signals reduce threat score weight</li>
                    <li>Obfuscation multiplier amplifies capability scores</li>
                    <li>Final score capped at 100</li>
                </ul>
            </div>
            
            <div class="col-md-6">
                <h5 style="color: #e4e6eb;">Component Scores</h5>
                <table class="table table-dark">
                    <tr>
                        <td>Structural Analysis</td>
                        <td><strong>${structural}/100</strong></td>
                    </tr>
                    <tr>
                        <td>Behavioral Analysis</td>
                        <td><strong>${behavioral}/100</strong></td>
                    </tr>
                    <tr>
                        <td>Digital Signature</td>
                        <td>${hasSig ? '✓ Yes (-80% threat)' : '✗ No'}</td>
                    </tr>
                    <tr>
                        <td>Has Metadata</td>
                        <td>${hasBulk ? '✓ Yes' : '✗ No'}</td>
                    </tr>
                    <tr class="table-primary">
                        <td><strong>Final Score</strong></td>
                        <td><strong>${overall}/100</strong></td>
                    </tr>
                </table>
                
                <div class="alert alert-secondary mt-3">
                    <strong>Note:</strong> Primary threat driver is <strong>${data.scores.primary_driver}</strong>, 
                    which contributes the most to the overall score.
                </div>
            </div>
        </div>
    `;
}

// Display Binary DNA
function displayBinaryDNA(data) {
    const dnaDiv = document.getElementById('binaryDNA');
    
    const subsystem = data.features.ui_indicators.is_gui_subsystem ? 'GUI' : 
                     data.features.ui_indicators.is_console_subsystem ? 'Console' : 'Unknown';
    
    const avgEntropy = (data.sections.reduce((sum, s) => sum + s.entropy, 0) / data.sections.length).toFixed(2);
    
    const ordinalRatio = (data.features.iat_analysis.ordinal_ratio * 100).toFixed(1);
    
    const signer = data.features.trust_signals.has_signature ? '✓ Signed' : '✗ Unsigned';
    
    dnaDiv.innerHTML = `
        <h5 style="color: #e4e6eb; margin-bottom: 1rem;">Binary Characteristics</h5>
        <table class="table table-dark table-hover">
            <tr>
                <td><i class="fas fa-window-maximize"></i> Subsystem</td>
                <td><strong>${subsystem}</strong></td>
            </tr>
            <tr>
                <td><i class="fas fa-random"></i> Avg Entropy</td>
                <td><strong>${avgEntropy}</strong></td>
            </tr>
            <tr>
                <td><i class="fas fa-hashtag"></i> Ordinal Ratio</td>
                <td><strong>${ordinalRatio}%</strong></td>
            </tr>
            <tr>
                <td><i class="fas fa-certificate"></i> Signature</td>
                <td><strong>${signer}</strong></td>
            </tr>
            <tr>
                <td><i class="fas fa-cube"></i> Sections</td>
                <td><strong>${data.sections.length}</strong></td>
            </tr>
            <tr>
                <td><i class="fas fa-plug"></i> Total Imports</td>
                <td><strong>${data.features.iat_analysis.total_imports}</strong></td>
            </tr>
            <tr>
                <td><i class="fas fa-book"></i> DLLs</td>
                <td><strong>${data.features.iat_analysis.dll_count}</strong></td>
            </tr>
            <tr>
                <td><i class="fas fa-network-wired"></i> Network DLLs</td>
                <td>${data.features.ui_indicators.has_network_dlls ? '✓ Yes' : '✗ No'}</td>
            </tr>
            <tr>
                <td><i class="fas fa-desktop"></i> UI DLLs</td>
                <td>${data.features.ui_indicators.has_ui_dlls ? '✓ Yes' : '✗ No'}</td>
            </tr>
        </table>
    `;
    
    // Create DNA visualization chart
    const dnaCtx = document.getElementById('dnaChart');
    if (dnaCtx) {
        new Chart(dnaCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Entropy', 'Ordinal %', 'Trust'],
                datasets: [{
                    data: [
                        parseFloat(avgEntropy) * 12.5,  // Scale to 100
                        parseFloat(ordinalRatio),
                        data.features.trust_signals.has_signature ? 100 : 0
                    ],
                    backgroundColor: ['#ffc107', '#dc3545', '#28a745']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#e4e6eb' }
                    },
                    title: {
                        display: true,
                        text: 'Binary Profile',
                        color: '#e4e6eb'
                    }
                }
            }
        });
    }
}

// Display MITRE ATT&CK Matrix
function displayMitreMatrix(mitre) {
    const matrixDiv = document.getElementById('mitreMatrix');
    const badge = document.getElementById('mitreBadge');
    
    badge.textContent = mitre.total_techniques;
    
    if (mitre.total_techniques === 0) {
        matrixDiv.innerHTML = '<div class="alert alert-success"><i class="fas fa-check-circle"></i> No MITRE ATT&CK techniques detected</div>';
        return;
    }
    
    let html = '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> <strong>Warning:</strong> Matched MITRE ATT&CK techniques detected</div>';
    
    for (const [tactic, techniques] of Object.entries(mitre.matrix)) {
        html += `
            <div class="mitre-tactic" style="margin-bottom: 1.5rem;">
                <h5 style="color: #e4e6eb; background: rgba(220, 53, 69, 0.2); padding: 0.5rem; border-left: 4px solid #dc3545; margin-bottom: 1rem;">
                    <i class="fas fa-bullseye"></i> ${tactic}
                </h5>
        `;
        
        techniques.forEach(tech => {
            html += `
                <div class="mitre-technique" style="background: #2a2f42; padding: 1rem; margin: 0.5rem 0; border-radius: 8px; border-left: 3px solid #ffc107;">
                    <div style="display: flex; justify-content: space-between; align-items: start;">
                        <div style="flex: 1;">
                            <div style="margin-bottom: 0.5rem;">
                                <strong style="color: #ffc107; font-size: 1.1rem;">${tech.id}</strong> - 
                                <span style="color: #e4e6eb; font-weight: 600;">${tech.name}</span>
                            </div>
                            <p style="color: #b0b3b8; margin: 0.5rem 0;">${tech.description}</p>
                            <div style="margin-top: 0.5rem;">
                                <small style="color: #17a2b8;">
                                    <i class="fas fa-code"></i> Matched APIs: ${tech.matched_apis.join(', ')}
                                </small>
                            </div>
                        </div>
                        <div style="display: flex; gap: 0.5rem; align-items: center; margin-left: 1rem;">
                            <span class="badge ${tech.confidence === 'High' ? 'bg-danger' : 'bg-warning'}" style="font-size: 0.9rem;">
                                ${tech.confidence}
                            </span>
                            <a href="${tech.url}" target="_blank" class="btn btn-sm btn-outline-primary">
                                <i class="fas fa-external-link-alt"></i> View
                            </a>
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
    }
    
    matrixDiv.innerHTML = html;
}

// Display section table
function displaySectionTable(sections) {
    const tbody = document.getElementById('sectionTableBody');
    tbody.innerHTML = '';
    
    sections.forEach(section => {
        const row = tbody.insertRow();
        
        const levelEmoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'CLEAN': '✅'
        };
        
        row.innerHTML = `
            <td><strong>${section.name}</strong></td>
            <td>${section.entropy.toFixed(2)}</td>
            <td>${section.size_ratio.toFixed(2)}x</td>
            <td><code>${section.permissions}</code></td>
            <td><strong>${section.suspicion_score}</strong>/100</td>
            <td>${levelEmoji[section.suspicion_level]} ${section.suspicion_level}</td>
        `;
        
        if (section.is_suspicious) {
            row.style.background = 'rgba(220, 53, 69, 0.1)';
        }
    });
}

// Create section size distribution chart
function createSectionChart(sections) {
    const ctx = document.getElementById('sectionChart');
    if (!ctx) {
        console.warn('[WARN] sectionChart canvas not found');
        return;
    }
    
    new Chart(ctx.getContext('2d'), {
        type: 'pie',
        data: {
            labels: sections.map(s => s.name),
            datasets: [{
                data: sections.map(s => s.virtual_size),
                backgroundColor: [
                    '#667eea', '#764ba2', '#f093fb', '#4facfe',
                    '#43e97b', '#fa709a', '#fee140', '#30cfd0'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#e4e6eb' }
                },
                title: {
                    display: true,
                    text: 'Section Size Distribution',
                    color: '#e4e6eb'
                }
            }
        }
    });
}

// Create entropy bar chart
function createEntropyChart(sections) {
    const ctx = document.getElementById('entropyChart');
    if (!ctx) {
        console.warn('[WARN] entropyChart canvas not found');
        return;
    }
    
    new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: sections.map(s => s.name),
            datasets: [{
                label: 'Entropy',
                data: sections.map(s => s.entropy),
                backgroundColor: sections.map(s => {
                    if (s.entropy > 7.5) return '#dc3545';
                    if (s.entropy > 6.5) return '#ffc107';
                    return '#28a745';
                })
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 8,
                    ticks: { color: '#e4e6eb' },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                },
                x: {
                    ticks: { color: '#e4e6eb' },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                }
            },
            plugins: {
                legend: { labels: { color: '#e4e6eb' } },
                title: {
                    display: true,
                    text: 'Section Entropy Levels',
                    color: '#e4e6eb'
                }
            }
        }
    });
}

// Create entropy heatmap
function createEntropyHeatmap(sections) {
    const heatmapPlot = document.getElementById('heatmapPlot');
    if (!heatmapPlot) {
        console.warn('[WARN] heatmapPlot div not found');
        return;
    }
    
    const heatmapData = [];
    
    sections.forEach((section) => {
        if (section.segment_analysis && section.segment_analysis.entropies) {
            const entropies = section.segment_analysis.entropies;
            const chunkSize = section.segment_analysis.chunk_size_kb || 4;
            
            entropies.forEach((entropy, chunkIdx) => {
                heatmapData.push({
                    section: section.name,
                    offset: chunkIdx * chunkSize,
                    entropy: entropy
                });
            });
        }
    });
    
    if (heatmapData.length === 0) {
        heatmapPlot.innerHTML = '<p class="text-center text-secondary">No heatmap data available</p>';
        return;
    }
    
    // Prepare data for Plotly
    const sectionNames = [...new Set(heatmapData.map(d => d.section))];
    const z = [];
    const x = [];
    const y = [];
    
    sectionNames.forEach(section => {
        const sectionData = heatmapData.filter(d => d.section === section);
        const entropies = sectionData.map(d => d.entropy);
        const offsets = sectionData.map(d => d.offset);
        
        z.push(entropies);
        if (x.length === 0) {
            x.push(...offsets);
        }
        y.push(section);
    });
    
    const trace = {
        z: z,
        x: x,
        y: y,
        type: 'heatmap',
        colorscale: [
            [0, '#28a745'],
            [0.5, '#ffc107'],
            [0.75, '#fd7e14'],
            [1, '#dc3545']
        ],
        colorbar: {
            title: 'Entropy',
            titleside: 'right',
            tickfont: { color: '#e4e6eb' },
            titlefont: { color: '#e4e6eb' }
        }
    };
    
    const layout = {
        title: 'Entropy Distribution Heatmap',
        xaxis: { title: 'Offset (KB)', color: '#e4e6eb' },
        yaxis: { title: 'Section', color: '#e4e6eb' },
        paper_bgcolor: '#1a1d29',
        plot_bgcolor: '#1a1d29',
        font: { color: '#e4e6eb' }
    };
    
    Plotly.newPlot(heatmapPlot, [trace], layout);
}

// Display capabilities
function displayCapabilities(capabilities) {
    const container = document.getElementById('capabilitiesContainer');
    
    if (capabilities.length === 0) {
        container.innerHTML = '<p class="text-success">✓ No malicious capabilities detected</p>';
        return;
    }
    
    container.innerHTML = '<div class="alert alert-danger">⚠️ <strong>Warning:</strong> Malicious capabilities detected</div>';
    
    capabilities.forEach(cap => {
        const badge = document.createElement('div');
        badge.className = 'capability-badge';
        badge.innerHTML = `
            <strong>${cap.description}</strong><br>
            <small>Score: ${cap.score} | APIs: ${cap.matched_apis.join(', ')}</small>
        `;
        container.appendChild(badge);
    });
}

// Display verdict
function displayVerdict(verdict) {
    const container = document.getElementById('verdictContainer');
    
    if (verdict.is_likely_malicious) {
        container.innerHTML = '<div class="alert alert-danger"><strong>⚠️ LIKELY MALICIOUS</strong></div>';
    } else {
        container.innerHTML = '<div class="alert alert-success"><strong>✓ Likely Benign</strong></div>';
    }
    
    const reasonsList = document.createElement('ul');
    verdict.reasons.forEach(reason => {
        const li = document.createElement('li');
        li.textContent = reason;
        reasonsList.appendChild(li);
    });
    
    container.appendChild(reasonsList);
}

// Utility: Format bytes
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}