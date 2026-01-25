/**
 * Chart generation utilities for PE-Sentinel
 * Handles all Chart.js visualizations
 */

// Create section size distribution pie chart
function createSectionChart(sections) {
    const ctx = document.getElementById('sectionChart');
    if (!ctx) return;
    
    // Destroy existing chart if any
    if (window.sectionChartInstance) {
        window.sectionChartInstance.destroy();
    }
    
    window.sectionChartInstance = new Chart(ctx.getContext('2d'), {
        type: 'pie',
        data: {
            labels: sections.map(s => s.name),
            datasets: [{
                data: sections.map(s => s.virtual_size),
                backgroundColor: [
                    '#667eea',
                    '#764ba2',
                    '#f093fb',
                    '#4facfe',
                    '#43e97b',
                    '#fa709a',
                    '#fee140',
                    '#30cfd0'
                ],
                borderWidth: 2,
                borderColor: '#1a1d29'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#e4e6eb',
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Section Size Distribution',
                    color: '#e4e6eb',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${formatBytes(value)} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Create entropy bar chart
function createEntropyChart(sections) {
    const ctx = document.getElementById('entropyChart');
    if (!ctx) return;
    
    // Destroy existing chart if any
    if (window.entropyChartInstance) {
        window.entropyChartInstance.destroy();
    }
    
    window.entropyChartInstance = new Chart(ctx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: sections.map(s => s.name),
            datasets: [{
                label: 'Entropy',
                data: sections.map(s => s.entropy),
                backgroundColor: sections.map(s => {
                    if (s.entropy > 7.5) return '#dc3545';
                    if (s.entropy > 6.5) return '#ffc107';
                    if (s.entropy > 5.5) return '#17a2b8';
                    return '#28a745';
                }),
                borderColor: sections.map(s => {
                    if (s.entropy > 7.5) return '#b02a37';
                    if (s.entropy > 6.5) return '#d39e00';
                    if (s.entropy > 5.5) return '#138496';
                    return '#1e7e34';
                }),
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 8,
                    ticks: {
                        color: '#e4e6eb',
                        callback: function(value) {
                            return value.toFixed(1);
                        }
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    title: {
                        display: true,
                        text: 'Entropy Value',
                        color: '#e4e6eb'
                    }
                },
                x: {
                    ticks: {
                        color: '#e4e6eb'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Section Entropy Levels',
                    color: '#e4e6eb',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Entropy: ${context.parsed.y.toFixed(2)}`;
                        },
                        afterLabel: function(context) {
                            const entropy = context.parsed.y;
                            if (entropy > 7.5) return 'Very High (Likely Packed)';
                            if (entropy > 6.5) return 'High (Suspicious)';
                            if (entropy > 5.5) return 'Moderate';
                            return 'Normal';
                        }
                    }
                }
            }
        }
    });
}

// Create suspicion score radar chart
function createSuspicionRadarChart(sections) {
    const ctx = document.getElementById('suspicionRadar');
    if (!ctx) return;
    
    // Destroy existing chart if any
    if (window.suspicionRadarInstance) {
        window.suspicionRadarInstance.destroy();
    }
    
    window.suspicionRadarInstance = new Chart(ctx.getContext('2d'), {
        type: 'radar',
        data: {
            labels: sections.map(s => s.name),
            datasets: [{
                label: 'Suspicion Score',
                data: sections.map(s => s.suspicion_score),
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
            maintainAspectRatio: true,
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        color: '#e4e6eb',
                        stepSize: 20
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    pointLabels: {
                        color: '#e4e6eb',
                        font: {
                            size: 12
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
                    text: 'Section Threat Scores',
                    color: '#e4e6eb',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                }
            }
        }
    });
}

// Utility function for formatting bytes
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}