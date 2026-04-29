// HeuristiX Chrome Extension - Popup Script
// Standalone version - runs scanner locally in JavaScript

// DOM Elements
const currentUrlEl = document.getElementById('currentUrl');
const statusEl = document.getElementById('status');
const resultEl = document.getElementById('result');
const scanBtn = document.getElementById('scanBtn');
const scoreEl = document.getElementById('score');
const verdictEl = document.getElementById('verdict');
const confidenceEl = document.getElementById('confidence');
const threatsListEl = document.getElementById('threatsList');

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  await getCurrentUrl();
});

// Get current tab URL
async function getCurrentUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentUrlEl.textContent = tab.url;
    }
  } catch (error) {
    currentUrlEl.textContent = 'Unable to get URL';
  }
}

// Start scan
scanBtn.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    showStatus('error', '❌', 'Unable to get current tab URL');
    return;
  }
  
  await startScan(tab.id, tab.url);
});

// Start scan locally
async function startScan(tabId, url) {
  try {
    showStatus('loading', '⏳', 'Scanning...');
    scanBtn.disabled = true;
    
    // Inject content script if not already loaded
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        files: ['content.js']
      });
    } catch (e) {
      // Script might already be injected, continue
    }
    
    // Wait a moment for script to initialize
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Get page content from content script
    const content = await chrome.tabs.sendMessage(tabId, { action: 'getPageContent' });
    
    if (!content) {
      throw new Error('Failed to get page content');
    }
    
    // Run local scanner
    const result = runLocalScan(content, url);
    
    displayResults(result);
    scanBtn.disabled = false;
    
  } catch (error) {
    showStatus('error', '❌', 'Scan failed: ' + error.message);
    scanBtn.disabled = false;
  }
}

// Run local scanner using ported detection logic
function runLocalScan(content, url) {
  const allThreats = [];
  
  // Analyze page HTML for phishing
  const phishingThreats = PhishingDetector.analyzePage(content.html, url, url);
  allThreats.push(...phishingThreats);
  
  // Analyze inline scripts for malware
  content.scripts.forEach(script => {
    if (script.type === 'inline' && script.content) {
      const malwareThreats = MalwareDetector.analyzeContent(script.content, url, url);
      allThreats.push(...malwareThreats);
    }
  });
  
  // Analyze links
  const linkThreats = SuspiciousLinkDetector.analyzeLinks(content.links, content.html, url, url);
  allThreats.push(...linkThreats);
  
  // Calculate risk score
  const riskScore = RiskScorer.score(allThreats);
  
  // Count severity
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  allThreats.forEach(t => {
    severityCounts[t.severity] = (severityCounts[t.severity] || 0) + 1;
  });
  
  return {
    base_url: url,
    pages_scanned: 1,
    files_scanned: content.scripts.length,
    scripts_scanned: content.scripts.filter(s => s.type === 'inline').length,
    links_checked: content.links.length,
    threats_found: allThreats.length,
    severity_counts: severityCounts,
    threats: allThreats.map(t => t.toDict()),
    risk_score: riskScore
  };
}

// Display scan results
function displayResults(result) {
  statusEl.style.display = 'none';
  resultEl.classList.add('show');
  
  const riskScore = result.risk_score || {};
  const score = riskScore.score || 0;
  const verdict = riskScore.verdict || 'Unknown';
  const confidence = riskScore.confidence || {};
  
  // Set score color
  scoreEl.className = 'score';
  if (score > 70) {
    scoreEl.classList.add('safe');
  } else if (score > 50) {
    scoreEl.classList.add('moderate');
  } else {
    scoreEl.classList.add('dangerous');
  }
  
  // Set verdict color
  verdictEl.className = 'verdict';
  if (score > 70) {
    verdictEl.classList.add('safe');
  } else if (score > 50) {
    verdictEl.classList.add('moderate');
  } else {
    verdictEl.classList.add('dangerous');
  }
  
  scoreEl.textContent = score;
  verdictEl.textContent = verdict;
  confidenceEl.textContent = confidence.label || '';
  
  // Display threats
  const threats = result.threats || [];
  if (threats.length === 0) {
    threatsListEl.innerHTML = '<div class="no-threats">✓ No threats detected</div>';
  } else {
    threatsListEl.innerHTML = threats.map(threat => `
      <div class="threat-item">
        <span class="threat-severity ${threat.severity}">${threat.severity.toUpperCase()}</span>
        <span class="threat-type">${threat.type}</span>
        <div class="threat-desc">${threat.description}</div>
      </div>
    `).join('');
  }
}

// Show status message
function showStatus(type, icon, text) {
  statusEl.style.display = 'block';
  resultEl.classList.remove('show');
  statusEl.className = 'status ' + type;
  statusEl.innerHTML = `
    <div class="status-icon">${icon}</div>
    <div class="status-text">${text}</div>
  `;
}
