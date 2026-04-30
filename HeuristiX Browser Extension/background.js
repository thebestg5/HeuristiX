// HeuristiX Chrome Extension - Background Service Worker
// Handles extension lifecycle and tab events

chrome.runtime.onInstalled.addListener(() => {
  console.log('HeuristiX Security Scanner extension installed');
  
  // Set default settings
  chrome.storage.local.get('autoScan', (data) => {
    if (data.autoScan === undefined) {
      chrome.storage.local.set({ autoScan: false });
    }
  });
});

// Optional: Add context menu to scan from right-click
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'scan-page',
    title: 'Scan this page with HeuristiX',
    contexts: ['page']
  });
});

// Handle context menu click
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'scan-page') {
    chrome.action.openPopup();
  }
});

// Auto-scan on page load
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Check if auto-scan is enabled
    chrome.storage.local.get(['autoScan', 'blockDangerous'], (data) => {
      if (data.autoScan && tab.url.startsWith('http')) {
        // Wait a moment for page to fully load, then inject and scan
        setTimeout(() => {
          performAutoScan(tabId, tab.url);
        }, 1000);
      }
      
      // Check if this URL is in the blocked list
      checkBlockedSites(tabId, tab.url);
    });
  }
});

// Check if site should be blocked
async function checkBlockedSites(tabId, url) {
  try {
    const data = await chrome.storage.local.get(['blockDangerous', 'blockedSites']);
    
    if (!data.blockDangerous) return;
    
    const blockedSites = data.blockedSites || {};
    if (blockedSites[url]) {
      // Block the site by redirecting to a warning page
      chrome.tabs.update(tabId, { url: chrome.runtime.getURL('blocked.html?url=' + encodeURIComponent(url)) });
    }
  } catch (error) {
    console.error('Error checking blocked sites:', error);
  }
}

async function performAutoScan(tabId, url) {
  try {
    // Inject content script
    await chrome.scripting.executeScript({
      target: { tabId: tabId },
      files: ['content.js']
    });
    
    // Wait for script to initialize
    await new Promise(resolve => setTimeout(resolve, 200));
    
    // Get page content
    const content = await chrome.tabs.sendMessage(tabId, { action: 'getPageContent' });
    
    if (content) {
      // Run local scanner (need to import scanner logic)
      // For now, just show a notification that auto-scan ran
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: (scanResult) => {
          // Show a small badge or notification
          console.log('HeuristiX auto-scan completed');
        }
      });
    }
  } catch (error) {
    console.error('Auto-scan failed:', error);
  }
}

// Update badge based on scan result
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'updateBadge') {
    const score = request.score;
    const tabId = sender.tab ? sender.tab.id : null;
    
    if (tabId) {
      // Set badge text to show score
      chrome.action.setBadgeText({
        text: score.toString(),
        tabId: tabId
      });
      
      // Set badge color based on score
      let color = '#22c55e'; // Green for safe
      if (score <= 50) color = '#ef4444'; // Red for dangerous
      else if (score <= 70) color = '#eab308'; // Yellow for moderate
      
      chrome.action.setBadgeBackgroundColor({
        color: color,
        tabId: tabId
      });
    }
  }
  
  if (request.action === 'clearBadge') {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      chrome.action.setBadgeText({ text: '', tabId: tabId });
    }
  }
  
  if (request.action === 'blockSite') {
    const url = request.url;
    chrome.storage.local.get('blockedSites', (data) => {
      const blockedSites = data.blockedSites || {};
      blockedSites[url] = { timestamp: Date.now(), score: request.score };
      chrome.storage.local.set({ blockedSites: blockedSites });
    });
  }
  
  if (request.action === 'unblockSite') {
    const url = request.url;
    chrome.storage.local.get('blockedSites', (data) => {
      const blockedSites = data.blockedSites || {};
      delete blockedSites[url];
      chrome.storage.local.set({ blockedSites: blockedSites });
    });
  }
  
  if (request.action === 'getBlockedSites') {
    chrome.storage.local.get('blockedSites', (data) => {
      sendResponse({ blockedSites: data.blockedSites || {} });
    });
    return true;
  }
  
  return true;
});
