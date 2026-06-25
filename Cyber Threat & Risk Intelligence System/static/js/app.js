/**
 * ============================================================
 *  app.js — Frontend Application Logic
 *  Cyber Risk & Threat Intelligence System
 * ============================================================
 *  Handles:
 *    - Socket.IO connection for real-time communication
 *    - Mode switching between File Upload and Live Capture
 *    - Drag-and-drop PCAP file upload with AJAX
 *    - Chart.js live-updating line graph for packet throughput
 *    - Threat results table rendering with risk badges
 *    - Mitigation detail modal
 *    - Secure Vault log viewer
 *    - Toast notifications
 * ============================================================
 */

// ============================================================
// GLOBAL STATE
// ============================================================
const AppState = {
    currentMode: 'upload',      // 'upload' or 'live'
    captureActive: false,       // Is live capture running?
    totalPackets: 0,            // Total packet counter
    normalPackets: 0,           // Normal packet counter
    anomalousPackets: 0,        // Anomalous packet counter
    threats: [],                // Array of threat entries
    liveChartData: [],          // Live chart data points
    selectedThreat: null,       // Currently selected threat for modal
};

// ============================================================
// SOCKET.IO CONNECTION
// ============================================================
const socket = io();

socket.on('connect', () => {
    console.log('[WS] Connected to server');
    showToast('success', 'Connected to Cyber Risk Intelligence server');
    fetchSystemStatus();
});

socket.on('disconnect', () => {
    console.log('[WS] Disconnected from server');
    showToast('error', 'Disconnected from server');
    updateStatusIndicator('status-capture', false);
});

socket.on('connect_error', (err) => {
    console.error('[WS] Connection error:', err);
    showToast('error', 'Connection error — is the server running?');
});

// --- Live Capture Events ---
socket.on('capture_status', (data) => {
    if (data.status === 'started') {
        AppState.captureActive = true;
        updateCaptureUI(true);
        showToast('success', 'Live capture started');
    } else if (data.status === 'stopped') {
        AppState.captureActive = false;
        updateCaptureUI(false);
        showToast('info', 'Live capture stopped');
    } else if (data.status === 'already_running') {
        // Server is already capturing (e.g. from a previous page load)
        // Treat this as "started" so the UI stays in sync
        AppState.captureActive = true;
        updateCaptureUI(true);
        showToast('warning', 'Capture is already running');
    }
});

socket.on('capture_error', (data) => {
    AppState.captureActive = false;
    updateCaptureUI(false);
    showToast('error', `Capture error: ${data.error}`);
});

socket.on('packet_data', (packet) => {
    // Only process packets if the user has clicked "Start Capture"
    if (!AppState.captureActive) return;
    handleLivePacket(packet);
});

// ============================================================
// INITIALIZATION
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    initModeSelector();
    initUploadZone();
    initLiveCapture();
    initModal();
    initVault();
    initLiveChart();
    loadInterfaces();
    updateFooterTime();
    initThreatFilters();

    // Update footer time every second
    setInterval(updateFooterTime, 1000);
});

// ============================================================
// SYSTEM STATUS
// ============================================================
function fetchSystemStatus() {
    fetch('/status')
        .then(res => res.json())
        .then(data => {
            updateStatusIndicator('status-ml', data.ml_model_loaded);
            updateStatusIndicator('status-prolog', data.prolog_ready);
            updateStatusIndicator('status-capture', data.capture_active);
            updateStatusIndicator('status-vault', true); // Vault is always ready

            if (!data.ml_model_loaded) {
                showToast('warning', 'ML model not loaded — run train_model.py first');
            }
            if (!data.prolog_ready) {
                showToast('warning', 'Prolog engine unavailable — using fallback diagnosis');
            }
        })
        .catch(err => {
            console.error('[STATUS] Failed to fetch:', err);
        });
}

function updateStatusIndicator(elementId, isOnline) {
    const el = document.getElementById(elementId);
    if (el) {
        el.classList.remove('online', 'offline');
        el.classList.add(isOnline ? 'online' : 'offline');
    }
}

// ============================================================
// MODE SELECTOR
// ============================================================
function initModeSelector() {
    const btnUpload = document.getElementById('btn-mode-upload');
    const btnLive = document.getElementById('btn-mode-live');

    btnUpload.addEventListener('click', () => switchMode('upload'));
    btnLive.addEventListener('click', () => switchMode('live'));
}

function switchMode(mode) {
    AppState.currentMode = mode;

    // Update button states
    document.querySelectorAll('.mode-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === mode);
    });

    // Toggle panels
    const panelUpload = document.getElementById('panel-upload');
    const panelLive = document.getElementById('panel-live');

    panelUpload.style.display = mode === 'upload' ? 'block' : 'none';
    panelLive.style.display = mode === 'live' ? 'block' : 'none';
}

// ============================================================
// MODE 1: FILE UPLOAD
// ============================================================
function initUploadZone() {
    const zone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('pcap-file-input');
    const clearBtn = document.getElementById('btn-clear-upload');

    // Click to browse
    zone.addEventListener('click', () => fileInput.click());

    // File selected
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            uploadPcapFile(e.target.files[0]);
        }
    });

    // Drag & Drop
    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('drag-over');
    });

    zone.addEventListener('dragleave', () => {
        zone.classList.remove('drag-over');
    });

    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            uploadPcapFile(e.dataTransfer.files[0]);
        }
    });

    // Clear upload
    clearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        resetUploadUI();
    });
}

function uploadPcapFile(file) {
    // Validate file extension
    const validExtensions = ['.pcap', '.pcapng', '.cap'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!validExtensions.includes(ext)) {
        showToast('error', `Invalid file type "${ext}". Use .pcap, .pcapng, or .cap`);
        return;
    }

    // Show progress
    const progress = document.getElementById('upload-progress');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');

    progress.classList.add('active');
    progressBar.classList.add('indeterminate');
    progressText.textContent = `Analyzing ${file.name}...`;

    // Show filename info
    const uploadInfo = document.getElementById('upload-info');
    const uploadFilename = document.getElementById('upload-filename');
    uploadFilename.textContent = `📁 ${file.name} (${formatFileSize(file.size)})`;
    uploadInfo.style.display = 'flex';

    showToast('info', `Uploading ${file.name} for analysis...`);

    // Upload via AJAX
    const formData = new FormData();
    formData.append('pcap_file', file);

    fetch('/upload', {
        method: 'POST',
        body: formData,
    })
        .then(res => res.json())
        .then(data => {
            progress.classList.remove('active');
            progressBar.classList.remove('indeterminate');

            if (data.error) {
                showToast('error', data.error);
                return;
            }

            showToast('success',
                `Analysis complete: ${data.total_packets} packets, ` +
                `${data.anomalous_packets} anomalous`
            );

            // Update stats
            AppState.totalPackets = data.total_packets;
            AppState.normalPackets = data.normal_packets;
            AppState.anomalousPackets = data.anomalous_packets;
            AppState.threats = data.threats || [];
            updateStatsBar();

            // Render results
            renderThreatTable(data.threats);
            renderAnalysisCharts(data);

            // Refresh vault
            fetchVaultLogs();
        })
        .catch(err => {
            progress.classList.remove('active');
            progressBar.classList.remove('indeterminate');
            showToast('error', `Upload failed: ${err.message}`);
            console.error('[UPLOAD] Error:', err);
        });
}

function resetUploadUI() {
    document.getElementById('pcap-file-input').value = '';
    document.getElementById('upload-info').style.display = 'none';
    document.getElementById('upload-progress').classList.remove('active');

    // Reset filters
    const typeSelect = document.getElementById('filter-threat-type');
    const riskSelect = document.getElementById('filter-risk-level');
    if (typeSelect) typeSelect.value = 'all';
    if (riskSelect) riskSelect.value = 'all';

    // Hide results
    document.getElementById('panel-results').style.display = 'none';
    document.getElementById('panel-chart').style.display = 'none';
}

// ============================================================
// MODE 2: LIVE CAPTURE
// ============================================================
function initLiveCapture() {
    const btnStart = document.getElementById('btn-start-capture');
    const btnStop = document.getElementById('btn-stop-capture');
    const select = document.getElementById('interface-select');

    btnStart.addEventListener('click', () => {
        const selectedInterface = select ? select.value : '';

        // Reset all counters and chart data BEFORE starting
        AppState.liveChartData = [];
        AppState.totalPackets = 0;
        AppState.normalPackets = 0;
        AppState.anomalousPackets = 0;
        AppState.threats = [];
        updateStatsBar();
        document.getElementById('live-packet-count').textContent = '0';

        // Clear the live chart
        if (liveChart) {
            liveChart.data.labels = [];
            liveChart.data.datasets[0].data = [];
            liveChart.data.datasets[1].data = [];
            liveChart.update('none');
        }

        // Hide old results table
        document.getElementById('panel-results').style.display = 'none';

        socket.emit('start_capture', { interface: selectedInterface });
    });

    btnStop.addEventListener('click', () => {
        socket.emit('stop_capture');
    });
}

function updateCaptureUI(isActive) {
    const btnStart = document.getElementById('btn-start-capture');
    const btnStop = document.getElementById('btn-stop-capture');

    btnStart.disabled = isActive;
    btnStop.disabled = !isActive;

    updateStatusIndicator('status-capture', isActive);
}

function handleLivePacket(packet) {
    AppState.totalPackets++;

    if (packet.is_anomalous) {
        AppState.anomalousPackets++;

        // Add to threats array
        AppState.threats.push(packet);

        // Show threat in results table
        renderThreatTable(AppState.threats);
        document.getElementById('panel-results').style.display = 'block';
    } else {
        AppState.normalPackets++;
    }

    // Update live counter
    document.getElementById('live-packet-count').textContent =
        AppState.totalPackets.toLocaleString();

    // Update stats bar
    updateStatsBar();

    // Update live chart
    addLiveChartPoint(packet);
}

// ============================================================
// STATS BAR
// ============================================================
function updateStatsBar() {
    animateCounter('stat-total-value', AppState.totalPackets);
    animateCounter('stat-normal-value', AppState.normalPackets);
    animateCounter('stat-anomalous-value', AppState.anomalousPackets);
}

function animateCounter(elementId, targetValue) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = targetValue.toLocaleString();
}

// ============================================================
// CHART.JS — LIVE LINE CHART
// ============================================================
let liveChart = null;

function initLiveChart() {
    const ctx = document.getElementById('live-chart');
    if (!ctx) return;

    const ctxCanvas = ctx.getContext('2d');
    const gradientBlue = ctxCanvas.createLinearGradient(0, 0, 0, 200);
    gradientBlue.addColorStop(0, 'rgba(99, 102, 241, 0.25)'); // Theme Primary Indigo
    gradientBlue.addColorStop(1, 'rgba(99, 102, 241, 0.0)');

    const gradientRed = ctxCanvas.createLinearGradient(0, 0, 0, 200);
    gradientRed.addColorStop(0, 'rgba(234, 67, 53, 0.18)'); // Gemini Red
    gradientRed.addColorStop(1, 'rgba(234, 67, 53, 0.0)');

    // Chart.js defaults
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.06)';
    Chart.defaults.font.family = "'Inter', sans-serif";

    liveChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Packet Length',
                    data: [],
                    borderColor: '#6366f1',
                    backgroundColor: gradientBlue,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHitRadius: 10,
                },
                {
                    label: 'Anomalies',
                    data: [],
                    borderColor: '#ea4335',
                    backgroundColor: gradientRed,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.1,
                    pointRadius: 4,
                    pointBackgroundColor: '#ea4335',
                    pointBorderColor: '#ea4335',
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 250 },
            interaction: {
                intersect: false,
                mode: 'index',
            },
            scales: {
                x: {
                    display: true,
                    grid: { color: 'rgba(99, 102, 241, 0.06)' },
                    ticks: { color: '#94a3b8', font: { family: 'Inter', size: 10 }, maxTicksLimit: 15 },
                },
                y: {
                    display: true,
                    grid: { color: 'rgba(99, 102, 241, 0.06)' },
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } },
                    beginAtZero: true,
                },
            },
            plugins: {
                legend: {
                    labels: {
                        usePointStyle: true,
                        pointStyle: 'circle',
                        padding: 20,
                        font: { size: 11, family: 'Inter' },
                    },
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 15, 45, 0.9)',
                    titleColor: '#e2e8f0',
                    bodyColor: '#94a3b8',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12,
                    titleFont: { family: 'Inter', weight: 600 },
                    bodyFont: { family: 'JetBrains Mono', size: 12 },
                }
            },
        },
    });
}

function addLiveChartPoint(packet) {
    if (!liveChart) return;

    const MAX_POINTS = 100;
    const now = new Date();
    const label = now.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    });

    // Add data points
    liveChart.data.labels.push(label);
    liveChart.data.datasets[0].data.push(packet.length || 0);
    liveChart.data.datasets[1].data.push(packet.is_anomalous ? (packet.length || 50) : 0);

    // Keep last MAX_POINTS points
    if (liveChart.data.labels.length > MAX_POINTS) {
        liveChart.data.labels.shift();
        liveChart.data.datasets[0].data.shift();
        liveChart.data.datasets[1].data.shift();
    }

    liveChart.update('none'); // Skip animation for performance
}

// ============================================================
// CHART.JS — ANALYSIS CHARTS (File Upload Mode)
// ============================================================
let timelineChart = null;
let pieThreatChart = null;
let threatTypesChart = null;
let riskLevelsChart = null;

function renderAnalysisCharts(data) {
    const chartPanel = document.getElementById('panel-chart');
    chartPanel.style.display = 'block';

    // --- Timeline Chart ---
    renderTimelineChart(data.packet_timeline || []);

    // --- Threat Distribution Pie Chart ---
    renderThreatPieChart(data.threats || []);

    // --- Threat Types Histogram ---
    renderThreatTypesChart(data.threats || []);

    // --- Risk Levels Histogram ---
    renderRiskLevelsChart(data.threats || []);
}

function renderTimelineChart(timeline) {
    const ctx = document.getElementById('timeline-chart');
    if (!ctx) return;

    // Destroy previous chart if exists
    if (timelineChart) timelineChart.destroy();

    const ctxCanvas = ctx.getContext('2d');
    const gradientBlue = ctxCanvas.createLinearGradient(0, 0, 0, 250);
    gradientBlue.addColorStop(0, 'rgba(99, 102, 241, 0.25)'); // Theme Primary Indigo
    gradientBlue.addColorStop(1, 'rgba(99, 102, 241, 0.0)');

    const labels = timeline.map((_, i) => i + 1);
    const lengths = timeline.map(p => p.length);
    const anomalyPoints = timeline.map(p => p.is_anomalous ? p.length : null);

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Packet Length',
                    data: lengths,
                    borderColor: '#6366f1',
                    backgroundColor: gradientBlue,
                    borderWidth: 1.5,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                },
                {
                    label: 'Anomalous',
                    data: anomalyPoints,
                    borderColor: '#ea4335',
                    backgroundColor: 'rgba(234, 67, 53, 0.2)',
                    borderWidth: 0,
                    fill: true,
                    pointRadius: 3,
                    pointBackgroundColor: '#ea4335',
                    spanGaps: false,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    display: true,
                    title: { display: true, text: 'Packet #', color: '#94a3b8', font: { family: 'Inter', size: 11 } },
                    grid: { color: 'rgba(99, 102, 241, 0.06)' },
                    ticks: { color: '#94a3b8', maxTicksLimit: 20, font: { family: 'Inter', size: 10 } },
                },
                y: {
                    display: true,
                    title: { display: true, text: 'Length (bytes)', color: '#94a3b8', font: { family: 'Inter', size: 11 } },
                    grid: { color: 'rgba(99, 102, 241, 0.06)' },
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } },
                    beginAtZero: true,
                },
            },
            plugins: {
                legend: {
                    labels: { usePointStyle: true, padding: 15, font: { size: 11, family: 'Inter' } },
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 15, 45, 0.9)',
                    titleColor: '#e2e8f0',
                    bodyColor: '#94a3b8',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12,
                    titleFont: { family: 'Inter', weight: 600 },
                    bodyFont: { family: 'JetBrains Mono', size: 12 },
                }
            },
        },
    });
}

function renderThreatPieChart(threats) {
    const ctx = document.getElementById('threat-pie-chart');
    if (!ctx) return;

    if (pieThreatChart) pieThreatChart.destroy();

    // Count threats by type
    const typeCounts = {};
    threats.forEach(t => {
        const type = (t.threat_type || 'unknown').replace(/_/g, ' ');
        typeCounts[type] = (typeCounts[type] || 0) + 1;
    });

    const labels = Object.keys(typeCounts);
    const values = Object.values(typeCounts);

    // Premium custom Gemini colors (translucent background with matching solid border)
    const backgroundColors = [
        'rgba(234, 67, 53, 0.7)',   // critical (red)
        'rgba(245, 158, 11, 0.7)',   // high (orange)
        'rgba(251, 188, 5, 0.7)',    // medium (yellow)
        'rgba(52, 168, 83, 0.7)',    // low (green)
        'rgba(66, 133, 244, 0.7)',   // info (blue)
        'rgba(139, 92, 246, 0.7)',   // purple
        'rgba(236, 72, 153, 0.7)',   // pink
        'rgba(6, 182, 212, 0.7)',    // cyan
        'rgba(16, 185, 129, 0.7)',   // emerald
        'rgba(59, 130, 246, 0.7)',   // blue
    ];

    const borderColors = [
        '#ea4335',
        '#f59e0b',
        '#fbbc05',
        '#34a853',
        '#4285f4',
        '#8b5cf6',
        '#ec4899',
        '#06b6d4',
        '#10b981',
        '#3b82f6',
    ];

    pieThreatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: backgroundColors.slice(0, labels.length),
                borderColor: borderColors.slice(0, labels.length),
                borderWidth: 2,
                borderRadius: 6,
                spacing: 5,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        usePointStyle: true,
                        pointStyle: 'circle',
                        padding: 15,
                        font: { size: 11, family: 'Inter', weight: 500 },
                        color: '#94a3b8',
                    },
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 15, 45, 0.9)',
                    titleColor: '#e2e8f0',
                    bodyColor: '#94a3b8',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12,
                    titleFont: { family: 'Inter', weight: 600 },
                    bodyFont: { family: 'JetBrains Mono', size: 12 },
                }
            },
        },
    });
}

function renderThreatTypesChart(threats) {
    const ctx = document.getElementById('threat-types-chart');
    if (!ctx) return;

    if (threatTypesChart) threatTypesChart.destroy();

    // Count threat types
    const typeCounts = {};
    threats.forEach(t => {
        const type = formatThreatType(t.threat_type || 'unknown');
        typeCounts[type] = (typeCounts[type] || 0) + 1;
    });

    const labels = Object.keys(typeCounts);
    const values = Object.values(typeCounts);

    // Sequential colors matching Sudoku project
    const bgColors = [
        'rgba(99, 102, 241, 0.7)',  // Indigo
        'rgba(168, 85, 247, 0.7)',  // Purple
        'rgba(34, 211, 238, 0.7)',  // Cyan
        'rgba(245, 158, 11, 0.7)',  // Amber
        'rgba(236, 72, 153, 0.7)',  // Pink
        'rgba(16, 185, 129, 0.7)'   // Emerald
    ];

    const borderColors = [
        '#6366f1',
        '#a855f7',
        '#22d3ee',
        '#f59e0b',
        '#ec4899',
        '#10b981'
    ];

    threatTypesChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: bgColors.slice(0, labels.length),
                borderColor: borderColors.slice(0, labels.length),
                borderWidth: 2,
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(15, 15, 45, 0.9)',
                    titleColor: '#e2e8f0',
                    bodyColor: '#94a3b8',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12,
                    titleFont: { family: 'Inter', weight: 600 },
                    bodyFont: { family: 'JetBrains Mono', size: 12 },
                }
            },
            scales: {
                x: {
                    ticks: { color: '#94a3b8', font: { family: 'Inter', size: 10 } },
                    grid: { color: 'rgba(99, 102, 241, 0.06)' },
                },
                y: {
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } },
                    grid: { color: 'rgba(99, 102, 241, 0.06)' },
                    beginAtZero: true,
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeOutQuart',
            }
        }
    });
}

function renderRiskLevelsChart(threats) {
    const ctx = document.getElementById('risk-levels-chart');
    if (!ctx) return;

    if (riskLevelsChart) riskLevelsChart.destroy();

    // Severity distribution
    const riskCounts = { 'critical': 0, 'high': 0, 'medium': 0, 'low': 0 };
    threats.forEach(t => {
        const level = (t.risk_level || 'low').toLowerCase();
        if (level in riskCounts) {
            riskCounts[level]++;
        }
    });

    const labels = ['Critical', 'High', 'Medium', 'Low'];
    const values = [riskCounts.critical, riskCounts.high, riskCounts.medium, riskCounts.low];

    // Colors matching standard categories
    const bgColors = [
        'rgba(234, 67, 53, 0.7)',   // Critical Red
        'rgba(245, 158, 11, 0.7)',   // High Amber/Orange
        'rgba(251, 188, 5, 0.7)',    // Medium Yellow
        'rgba(52, 168, 83, 0.7)'     // Low Green
    ];

    const borderColors = [
        '#ea4335',
        '#f59e0b',
        '#fbbc05',
        '#34a853'
    ];

    riskLevelsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: bgColors,
                borderColor: borderColors,
                borderWidth: 2,
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(15, 15, 45, 0.9)',
                    titleColor: '#e2e8f0',
                    bodyColor: '#94a3b8',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12,
                    titleFont: { family: 'Inter', weight: 600 },
                    bodyFont: { family: 'JetBrains Mono', size: 12 },
                }
            },
            scales: {
                x: {
                    ticks: { color: '#94a3b8', font: { family: 'Inter', size: 10 } },
                    grid: { color: 'rgba(99, 102, 241, 0.06)' },
                },
                y: {
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } },
                    grid: { color: 'rgba(99, 102, 241, 0.06)' },
                    beginAtZero: true,
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeOutQuart',
            }
        }
    });
}

// ============================================================
// THREAT TABLE RENDERING
// ============================================================
function renderThreatTable(threats, isFilteredView = false) {
    const panel = document.getElementById('panel-results');
    const tbody = document.getElementById('threat-table-body');
    const badge = document.getElementById('threat-count-badge');

    panel.style.display = 'block';

    // If this is NOT a filtered view, update the threat types dropdown dynamically
    if (!isFilteredView) {
        updateThreatTypeDropdown(threats);
        
        // Also apply filters immediately to respect any pre-selected filter values
        const selectedType = document.getElementById('filter-threat-type').value;
        const selectedRisk = document.getElementById('filter-risk-level').value;
        if (selectedType !== 'all' || selectedRisk !== 'all') {
            let filtered = threats;
            if (selectedType !== 'all') {
                filtered = filtered.filter(t => t.threat_type === selectedType);
            }
            if (selectedRisk !== 'all') {
                filtered = filtered.filter(t => (t.risk_level || 'low').toLowerCase() === selectedRisk);
            }
            badge.textContent = `${filtered.length} of ${threats.length} Threat${threats.length !== 1 ? 's' : ''}`;
            threats = filtered;
        } else {
            badge.textContent = `${threats.length} Threat${threats.length !== 1 ? 's' : ''}`;
        }
    } else {
        // If it is a filtered view, display the filtered count vs total count
        badge.textContent = `${threats.length} of ${AppState.threats.length} Threat${AppState.threats.length !== 1 ? 's' : ''}`;
    }

    tbody.innerHTML = '';

    if (threats.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="9">No threats matched the selected filters.</td>
            </tr>`;
        return;
    }

    threats.forEach((threat, index) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${threat.packet_no || index + 1}</td>
            <td>${escapeHtml(threat.src_ip || 'N/A')}</td>
            <td>${escapeHtml(threat.dst_ip || 'N/A')}</td>
            <td>${(threat.protocol || 'N/A').toUpperCase()}</td>
            <td>${threat.dst_port || 'N/A'}</td>
            <td>${formatThreatType(threat.threat_type)}</td>
            <td>${renderRiskBadge(threat.risk_level)}</td>
            <td>${((threat.confidence || 0) * 100).toFixed(1)}%</td>
            <td>
                <button class="btn-details" data-index="${index}"
                        id="btn-detail-${index}">
                    View
                </button>
            </td>`;

        // Add click handler for detail button
        tr.querySelector('.btn-details').addEventListener('click', () => {
            openThreatModal(threat);
        });

        tbody.appendChild(tr);
    });
}

// ============================================================
// DYNAMIC THREAT FILTERS
// ============================================================
function initThreatFilters() {
    const typeSelect = document.getElementById('filter-threat-type');
    const riskSelect = document.getElementById('filter-risk-level');

    if (typeSelect) {
        typeSelect.addEventListener('change', () => {
            renderThreatTable(AppState.threats, false);
        });
    }

    if (riskSelect) {
        riskSelect.addEventListener('change', () => {
            renderThreatTable(AppState.threats, false);
        });
    }
}

function updateThreatTypeDropdown(threats) {
    const select = document.getElementById('filter-threat-type');
    if (!select) return;

    // Remember currently selected value
    const currentValue = select.value;

    // Extract unique threat types
    const uniqueTypes = new Set();
    threats.forEach(t => {
        if (t.threat_type) {
            uniqueTypes.add(t.threat_type);
        }
    });

    // Clear and build new option list
    select.innerHTML = '<option value="all">All Threat Types</option>';
    
    // Sort types alphabetically for cleaner UX
    const sortedTypes = Array.from(uniqueTypes).sort();
    sortedTypes.forEach(type => {
        const opt = document.createElement('option');
        opt.value = type;
        opt.textContent = formatThreatType(type);
        select.appendChild(opt);
    });

    // Restore selection if still valid
    if (uniqueTypes.has(currentValue)) {
        select.value = currentValue;
    } else {
        select.value = 'all';
    }
}

function formatThreatType(type) {
    if (!type) return 'Unknown';
    return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function renderRiskBadge(level) {
    const l = (level || 'low').toLowerCase();
    return `<span class="risk-badge risk-${l}">${l.toUpperCase()}</span>`;
}

// ============================================================
// MITIGATION DETAIL MODAL
// ============================================================
function initModal() {
    const overlay = document.getElementById('modal-overlay');
    const btnClose = document.getElementById('btn-close-modal');
    const btnReport = document.getElementById('btn-generate-report');

    btnClose.addEventListener('click', closeModal);

    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) closeModal();
    });

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });

    btnReport.addEventListener('click', () => {
        if (AppState.selectedThreat && AppState.selectedThreat.id) {
            generateReport(AppState.selectedThreat.id);
        } else {
            showToast('warning', 'Report generation requires a vault entry ID');
        }
    });
}

function openThreatModal(threat) {
    AppState.selectedThreat = threat;

    const title = document.getElementById('modal-title');
    const body = document.getElementById('modal-body');

    title.textContent = `🔍 ${formatThreatType(threat.threat_type)} — Details`;

    body.innerHTML = `
        <div class="detail-row">
            <span class="detail-label">Threat Type</span>
            <span class="detail-value">${formatThreatType(threat.threat_type)}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Risk Level</span>
            <span class="detail-value">${renderRiskBadge(threat.risk_level)}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Source IP</span>
            <span class="detail-value">${escapeHtml(threat.src_ip || 'N/A')}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Destination IP</span>
            <span class="detail-value">${escapeHtml(threat.dst_ip || 'N/A')}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Protocol</span>
            <span class="detail-value">${(threat.protocol || 'N/A').toUpperCase()}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Destination Port</span>
            <span class="detail-value">${threat.dst_port || 'N/A'}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Packet Length</span>
            <span class="detail-value">${threat.length || 'N/A'} bytes</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">ML Prediction</span>
            <span class="detail-value">${escapeHtml(threat.prediction || 'N/A')}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Confidence</span>
            <span class="detail-value">${((threat.confidence || 0) * 100).toFixed(1)}%</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Timestamp</span>
            <span class="detail-value">${escapeHtml(threat.timestamp || 'N/A')}</span>
        </div>

        <h3 style="margin-top: 20px; color: var(--accent-green); font-family: var(--font-heading);
                    font-size: 13px; letter-spacing: 2px; text-transform: uppercase;">
            🔧 Mitigation Recommendations
        </h3>
        <div class="mitigation-box">
            ${escapeHtml(threat.mitigation || 'No specific mitigation available.')}
        </div>
    `;

    document.getElementById('modal-overlay').style.display = 'flex';
}

function closeModal() {
    document.getElementById('modal-overlay').style.display = 'none';
    AppState.selectedThreat = null;
}

// ============================================================
// SECURE VAULT VIEWER
// ============================================================
function initVault() {
    const btnRefresh = document.getElementById('btn-refresh-vault');
    btnRefresh.addEventListener('click', fetchVaultLogs);

    // Initial fetch
    fetchVaultLogs();
}

function fetchVaultLogs() {
    fetch('/logs')
        .then(res => res.json())
        .then(data => {
            const logs = data.logs || [];
            renderVaultTable(logs);

            // Update vault stat
            document.getElementById('stat-vault-value').textContent =
                logs.length.toLocaleString();
        })
        .catch(err => {
            console.error('[VAULT] Failed to fetch logs:', err);
        });
}

function renderVaultTable(logs) {
    const tbody = document.getElementById('vault-table-body');

    if (logs.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="6">No encrypted logs yet. Analyze traffic to populate.</td>
            </tr>`;
        return;
    }

    tbody.innerHTML = '';
    logs.forEach(log => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${log.id || 'N/A'}</td>
            <td>${formatTimestamp(log.timestamp)}</td>
            <td>${escapeHtml(log.src_ip || 'N/A')}</td>
            <td>${formatThreatType(log.threat_type)}</td>
            <td>${renderRiskBadge(log.risk_level)}</td>
            <td>
                <button class="btn-details" id="btn-report-${log.id}"
                        onclick="generateReport(${log.id})">
                    📄 PDF
                </button>
            </td>`;
        tbody.appendChild(tr);
    });
}

// ============================================================
// PDF REPORT GENERATION
// ============================================================
function generateReport(logId) {
    showToast('info', 'Generating PDF report...');

    // Trigger download via new window/tab
    window.open(`/report/${logId}`, '_blank');
}

// ============================================================
// TOAST NOTIFICATIONS
// ============================================================
function showToast(type, message, duration = 4000) {
    const container = document.getElementById('toast-container');

    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️',
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || 'ℹ️'}</span>
        <span class="toast-message">${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    // Auto-remove after duration
    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================
function escapeHtml(str) {
    if (typeof str !== 'string') return str;
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function formatTimestamp(ts) {
    if (!ts) return 'N/A';
    try {
        const d = new Date(ts);
        return d.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false,
        });
    } catch {
        return ts;
    }
}

function updateFooterTime() {
    const el = document.getElementById('footer-time');
    if (el) {
        const now = new Date();
        el.textContent = now.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false,
        });
    }
}

// ============================================================
// DYNAMIC NETWORK INTERFACE LOAD
// ============================================================
function loadInterfaces() {
    const select = document.getElementById('interface-select');
    if (!select) return;

    fetch('/interfaces')
        .then(res => res.json())
        .then(data => {
            select.innerHTML = '';
            
            const interfaces = data.interfaces || [];
            if (interfaces.length === 0) {
                select.innerHTML = '<option value="">No interfaces found</option>';
                return;
            }
            
            interfaces.forEach(iface => {
                const opt = document.createElement('option');
                opt.value = iface.name;
                opt.textContent = iface.friendly;
                
                // Auto-select Wi-Fi or Ethernet if present
                const lowerFriendly = iface.friendly.toLowerCase();
                if (lowerFriendly.includes('wi-fi') || lowerFriendly.includes('wireless') || lowerFriendly.includes('ethernet')) {
                    opt.selected = true;
                }
                
                select.appendChild(opt);
            });
        })
        .catch(err => {
            console.error('[INTERFACES] Failed to load:', err);
            select.innerHTML = '<option value="">Error loading interfaces</option>';
        });
}
