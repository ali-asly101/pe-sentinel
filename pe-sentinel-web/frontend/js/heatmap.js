/**
 * Heatmap visualization utilities for entropy analysis
 * Uses Plotly.js for interactive heatmaps
 */

// Create entropy heatmap using Plotly
function createEntropyHeatmap(sections) {
    const container = document.getElementById('heatmapPlot');
    if (!container) return;
    
    // Prepare data
    const heatmapData = [];
    
    sections.forEach((section) => {
        if (section.segment_analysis && section.segment_analysis.entropies) {
            const entropies = section.segment_analysis.entropies;
            const chunkSize = section.segment_analysis.chunk_size_kb || 4;
            
            entropies.forEach((entropy, chunkIdx) => {
                heatmapData.push({
                    section: section.name,
                    offset: chunkIdx * chunkSize,
                    entropy: entropy,
                    chunkIdx: chunkIdx
                });
            });
        }
    });
    
    if (heatmapData.length === 0) {
        container.innerHTML = '<p class="text-center text-secondary">No segment data available</p>';
        return;
    }
    
    // Group by section
    const sectionNames = [...new Set(heatmapData.map(d => d.section))];
    const z = [];
    const x = [];
    const y = sectionNames;
    
    // Find max offset for x-axis
    const maxOffset = Math.max(...heatmapData.map(d => d.offset));
    const maxChunks = Math.max(...heatmapData.map(d => d.chunkIdx));
    
    // Create x-axis labels (offsets in KB)
    for (let i = 0; i <= maxChunks; i++) {
        const offset = heatmapData.find(d => d.chunkIdx === i)?.offset || i * 4;
        x.push(offset);
    }
    
    // Build z-matrix (entropy values)
    sectionNames.forEach(section => {
        const sectionData = heatmapData.filter(d => d.section === section);
        const entropies = new Array(x.length).fill(0);
        
        sectionData.forEach(d => {
            entropies[d.chunkIdx] = d.entropy;
        });
        
        z.push(entropies);
    });
    
    // Create heatmap trace
    const trace = {
        z: z,
        x: x,
        y: y,
        type: 'heatmap',
        colorscale: [
            [0, '#28a745'],      // Green (low entropy)
            [0.4, '#17a2b8'],    // Cyan
            [0.6, '#ffc107'],    // Yellow
            [0.8, '#fd7e14'],    // Orange
            [1, '#dc3545']       // Red (high entropy)
        ],
        colorbar: {
            title: {
                text: 'Entropy',
                side: 'right'
            },
            titleside: 'right',
            tickmode: 'linear',
            tick0: 0,
            dtick: 1,
            thickness: 20,
            len: 0.7,
            tickfont: {
                color: '#e4e6eb'
            },
            titlefont: {
                color: '#e4e6eb'
            }
        },
        hovertemplate: '<b>%{y}</b><br>' +
                       'Offset: %{x} KB<br>' +
                       'Entropy: %{z:.2f}<br>' +
                       '<extra></extra>',
        zmin: 0,
        zmax: 8
    };
    
    // Layout configuration
    const layout = {
        title: {
            text: 'Entropy Distribution Heatmap',
            font: {
                color: '#e4e6eb',
                size: 18,
                weight: 'bold'
            }
        },
        xaxis: {
            title: {
                text: 'Offset (KB)',
                font: { color: '#e4e6eb' }
            },
            color: '#e4e6eb',
            gridcolor: 'rgba(255, 255, 255, 0.1)',
            tickfont: { color: '#e4e6eb' }
        },
        yaxis: {
            title: {
                text: 'Section',
                font: { color: '#e4e6eb' }
            },
            color: '#e4e6eb',
            gridcolor: 'rgba(255, 255, 255, 0.1)',
            tickfont: { color: '#e4e6eb' }
        },
        paper_bgcolor: '#1a1d29',
        plot_bgcolor: '#1a1d29',
        font: {
            color: '#e4e6eb',
            family: 'Segoe UI, sans-serif'
        },
        margin: {
            l: 80,
            r: 100,
            t: 80,
            b: 80
        },
        height: 400
    };
    
    // Plot configuration
    const config = {
        responsive: true,
        displayModeBar: true,
        displaylogo: false,
        modeBarButtonsToRemove: ['lasso2d', 'select2d'],
        toImageButtonOptions: {
            format: 'png',
            filename: 'entropy_heatmap',
            height: 800,
            width: 1200,
            scale: 2
        }
    };
    
    // Create plot
    Plotly.newPlot(container, [trace], layout, config);
}

// Create 3D surface plot for entropy (advanced visualization)
function createEntropy3DSurface(sections) {
    const container = document.getElementById('entropy3DPlot');
    if (!container) return;
    
    const surfaceData = [];
    
    sections.forEach((section, sectionIdx) => {
        if (section.segment_analysis && section.segment_analysis.entropies) {
            const entropies = section.segment_analysis.entropies;
            const chunkSize = section.segment_analysis.chunk_size_kb || 4;
            
            const x = entropies.map((_, idx) => idx * chunkSize);
            const y = entropies.map(() => sectionIdx);
            const z = entropies;
            
            surfaceData.push({
                section: section.name,
                x: x,
                y: y,
                z: z
            });
        }
    });
    
    if (surfaceData.length === 0) {
        container.innerHTML = '<p class="text-center text-secondary">No data available for 3D visualization</p>';
        return;
    }
    
    // Prepare 3D surface
    const x = surfaceData[0].x;
    const y = surfaceData.map((_, idx) => idx);
    const z = surfaceData.map(s => s.z);
    
    const trace = {
        x: x,
        y: y,
        z: z,
        type: 'surface',
        colorscale: [
            [0, '#28a745'],
            [0.5, '#ffc107'],
            [0.75, '#fd7e14'],
            [1, '#dc3545']
        ],
        colorbar: {
            title: 'Entropy',
            titleside: 'right'
        }
    };
    
    const layout = {
        title: '3D Entropy Surface',
        scene: {
            xaxis: { title: 'Offset (KB)' },
            yaxis: { title: 'Section Index' },
            zaxis: { title: 'Entropy' }
        },
        paper_bgcolor: '#1a1d29',
        plot_bgcolor: '#1a1d29',
        font: { color: '#e4e6eb' }
    };
    
    Plotly.newPlot(container, [trace], layout);
}

// Create entropy timeline chart
function createEntropyTimeline(sections) {
    const container = document.getElementById('entropyTimeline');
    if (!container) return;
    
    const traces = [];
    
    sections.forEach(section => {
        if (section.segment_analysis && section.segment_analysis.entropies) {
            const entropies = section.segment_analysis.entropies;
            const chunkSize = section.segment_analysis.chunk_size_kb || 4;
            
            const x = entropies.map((_, idx) => idx * chunkSize);
            const y = entropies;
            
            traces.push({
                x: x,
                y: y,
                mode: 'lines+markers',
                name: section.name,
                line: {
                    width: 2
                },
                marker: {
                    size: 4
                }
            });
        }
    });
    
    if (traces.length === 0) {
        container.innerHTML = '<p class="text-center text-secondary">No entropy timeline data available</p>';
        return;
    }
    
    const layout = {
        title: {
            text: 'Entropy Timeline by Section',
            font: { color: '#e4e6eb', size: 18 }
        },
        xaxis: {
            title: 'Offset (KB)',
            color: '#e4e6eb',
            gridcolor: 'rgba(255, 255, 255, 0.1)'
        },
        yaxis: {
            title: 'Entropy',
            color: '#e4e6eb',
            gridcolor: 'rgba(255, 255, 255, 0.1)',
            range: [0, 8]
        },
        paper_bgcolor: '#1a1d29',
        plot_bgcolor: '#1a1d29',
        font: { color: '#e4e6eb' },
        hovermode: 'closest',
        showlegend: true,
        legend: {
            font: { color: '#e4e6eb' },
            bgcolor: 'rgba(36, 41, 56, 0.8)'
        }
    };
    
    const config = {
        responsive: true,
        displayModeBar: true,
        displaylogo: false
    };
    
    Plotly.newPlot(container, traces, layout, config);
}
