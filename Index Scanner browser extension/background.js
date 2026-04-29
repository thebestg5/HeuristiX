// HeuristiX Chrome Extension - Background Service Worker
// Handles extension lifecycle and tab events

chrome.runtime.onInstalled.addListener(() => {
  console.log('HeuristiX Security Scanner extension installed');
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
