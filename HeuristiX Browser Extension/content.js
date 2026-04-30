// HeuristiX Content Script
// Extracts page content for scanning

function getPageContent() {
  // Get all scripts (inline and external)
  const scripts = [];
  document.querySelectorAll('script').forEach(script => {
    if (script.src) {
      scripts.push({ type: 'external', src: script.src });
    } else if (script.textContent) {
      scripts.push({ type: 'inline', content: script.textContent });
    }
  });
  
  // Get all links
  const links = [];
  document.querySelectorAll('a[href]').forEach(a => {
    links.push(a.href);
  });
  
  // Get all forms
  const forms = [];
  document.querySelectorAll('form').forEach(form => {
    const inputs = [];
    form.querySelectorAll('input, textarea, select').forEach(input => {
      inputs.push({
        type: input.type || 'text',
        name: input.name || '',
        id: input.id || ''
      });
    });
    forms.push({
      action: form.action || '',
      inputs: inputs
    });
  });
  
  // Get full HTML
  const html = document.documentElement.outerHTML;
  
  return {
    url: window.location.href,
    html: html,
    scripts: scripts,
    links: links,
    forms: forms
  };
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getPageContent') {
    const content = getPageContent();
    sendResponse(content);
  }
  return true;
});
