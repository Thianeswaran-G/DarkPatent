// Content Script for SecureGuard Extension - In-page scanning and protection

class ContentScriptGuard {
  constructor() {
    this.sensitiveSelectors = [
      'input[type="password"]',
      'input[type="email"]',
      'input[name*="ssn"]',
      'input[name*="social"]',
      'input[name*="credit"]',
      'input[name*="card"]',
      'input[name*="cvv"]',
      'input[name*="api"]',
      'textarea'
    ];
    
    this.monitoredElements = new Set();
    this.alertOverlay = null;
    this.currentAlerts = [];
    this.init();
  }

  init() {
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.setupMonitoring());
    } else {
      this.setupMonitoring();
    }
    
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      switch (message.type) {
        case 'SHOW_ALERT':
          this.showInPageAlert(message.alert);
          break;
        case 'BLOCK_SUBMISSION':
          this.blockFormSubmission(message.reason);
          break;
        case 'HIGHLIGHT_RISKS':
          this.highlightRiskyElements();
          break;
      }
    });
  }

  setupMonitoring() {
    // Monitor form submissions
    document.addEventListener('submit', (e) => this.handleFormSubmission(e), true);
    
    // Monitor input changes
    document.addEventListener('input', (e) => this.handleInputChange(e), true);
    
    // Monitor copy/paste events
    document.addEventListener('paste', (e) => this.handlePaste(e), true);
    document.addEventListener('copy', (e) => this.handleCopy(e), true);
    
    // Monitor autofill events
    document.addEventListener('change', (e) => this.handleAutofill(e), true);
    
    // Set up mutation observer for dynamic content
    this.setupMutationObserver();
    
    // Initial scan of existing elements
    this.scanExistingElements();
    
    // Check URL reputation
    this.checkCurrentPageSecurity();
  }

  async handleFormSubmission(event) {
    const form = event.target;
    if (!form || form.tagName !== 'FORM') return;
    
    // Extract form data
    const formData = new FormData(form);
    const dataString = Array.from(formData.entries())
      .map(([key, value]) => `${key}: ${value}`)
      .join(' ');
    
    // Scan for sensitive data
    const result = await chrome.runtime.sendMessage({
      type: 'SCAN_DATA',
      data: dataString
    });
    
    if (result && result.sensitiveData.length > 0) {
      // Show warning and potentially block submission
      const shouldBlock = await this.showSubmissionWarning(result, form.action || window.location.href);
      
      if (shouldBlock) {
        event.preventDefault();
        event.stopPropagation();
        return false;
      }
    }
  }

  handleInputChange(event) {
    const input = event.target;
    if (!this.isSensitiveInput(input)) return;
    
    const value = input.value;
    if (value.length > 10) { // Only check substantial input
      chrome.runtime.sendMessage({
        type: 'SCAN_DATA',
        data: value
      }).then(result => {
        if (result && result.sensitiveData.length > 0) {
          this.highlightElement(input, 'warning');
          this.showTooltipWarning(input, 'Sensitive data detected');
        }
      });
    }
  }

  handlePaste(event) {
    const pastedData = (event.clipboardData || window.clipboardData).getData('text');
    
    chrome.runtime.sendMessage({
      type: 'SCAN_DATA',
      data: pastedData
    }).then(result => {
      if (result && result.sensitiveData.length > 0) {
        this.showInPageAlert({
          type: 'paste_warning',
          message: 'Sensitive data detected in clipboard',
          severity: 'medium',
          data: result.sensitiveData
        });
      }
    });
  }

  handleCopy(event) {
    const selection = window.getSelection().toString();
    if (selection.length > 10) {
      chrome.runtime.sendMessage({
        type: 'SCAN_DATA',
        data: selection
      }).then(result => {
        if (result && result.sensitiveData.length > 0) {
          this.showInPageAlert({
            type: 'copy_warning',
            message: 'You are copying sensitive data',
            severity: 'low',
            data: result.sensitiveData
          });
        }
      });
    }
  }

  handleAutofill(event) {
    const input = event.target;
    if (input.tagName === 'INPUT' && event.isTrusted) {
      // Autofill detected
      setTimeout(() => {
        chrome.runtime.sendMessage({
          type: 'SCAN_DATA',
          data: input.value
        }).then(result => {
          if (result && result.sensitiveData.length > 0) {
            this.showTooltipWarning(input, 'Autofilled sensitive data');
          }
        });
      }, 100);
    }
  }

  setupMutationObserver() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            this.scanNewElement(node);
          }
        });
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  scanExistingElements() {
    this.sensitiveSelectors.forEach(selector => {
      document.querySelectorAll(selector).forEach(element => {
        this.monitorElement(element);
      });
    });
  }

  scanNewElement(element) {
    this.sensitiveSelectors.forEach(selector => {
      if (element.matches && element.matches(selector)) {
        this.monitorElement(element);
      }
      
      element.querySelectorAll && element.querySelectorAll(selector).forEach(child => {
        this.monitorElement(child);
      });
    });
  }

  monitorElement(element) {
    if (this.monitoredElements.has(element)) return;
    
    this.monitoredElements.add(element);
    
    // Add visual indicator for sensitive fields
    this.addSecurityIndicator(element);
  }

  isSensitiveInput(input) {
    const sensitiveTypes = ['password', 'email'];
    const sensitiveNames = ['ssn', 'social', 'credit', 'card', 'cvv', 'api'];
    
    return sensitiveTypes.includes(input.type) ||
           sensitiveNames.some(name => 
             input.name?.toLowerCase().includes(name) ||
             input.id?.toLowerCase().includes(name) ||
             input.className?.toLowerCase().includes(name)
           );
  }

  addSecurityIndicator(element) {
    const indicator = document.createElement('div');
    indicator.className = 'secureguard-indicator';
    indicator.innerHTML = '🛡️';
    indicator.style.cssText = `
      position: absolute;
      right: 5px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 12px;
      z-index: 10000;
      pointer-events: none;
      opacity: 0.6;
    `;
    
    const parent = element.parentElement;
    if (parent && getComputedStyle(parent).position === 'static') {
      parent.style.position = 'relative';
    }
    
    parent?.appendChild(indicator);
  }

  highlightElement(element, type) {
    const color = type === 'warning' ? '#ff9800' : '#f44336';
    element.style.borderColor = color;
    element.style.borderWidth = '2px';
    element.style.borderStyle = 'solid';
    element.style.boxShadow = `0 0 5px ${color}40`;
  }

  showTooltipWarning(element, message) {
    const tooltip = document.createElement('div');
    tooltip.className = 'secureguard-tooltip';
    tooltip.textContent = message;
    tooltip.style.cssText = `
      position: absolute;
      background: #333;
      color: white;
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 10001;
      max-width: 200px;
      word-wrap: break-word;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    `;
    
    const rect = element.getBoundingClientRect();
    tooltip.style.left = rect.left + 'px';
    tooltip.style.top = (rect.bottom + 5) + 'px';
    
    document.body.appendChild(tooltip);
    
    setTimeout(() => {
      tooltip.remove();
    }, 3000);
  }

  async showSubmissionWarning(scanResult, targetUrl) {
    return new Promise((resolve) => {
      const modal = this.createWarningModal(scanResult, targetUrl, resolve);
      document.body.appendChild(modal);
    });
  }

  createWarningModal(scanResult, targetUrl, callback) {
    // Remove any existing modals first
    const existingModals = document.querySelectorAll('.secureguard-modal');
    existingModals.forEach(modal => modal.remove());
    
    const modal = document.createElement('div');
    modal.className = 'secureguard-modal';
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.8);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: Arial, sans-serif;
    `;
    
    const content = document.createElement('div');
    content.style.cssText = `
      background: white;
      padding: 30px;
      border-radius: 8px;
      max-width: 500px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
      position: relative;
    `;
    
    const sensitiveDataList = scanResult.sensitiveData && scanResult.sensitiveData.length > 0 
      ? scanResult.sensitiveData.map(item => `<li>${item.type}: ${item.value ? item.value.substring(0, 20) + '...' : 'detected'}</li>`).join('')
      : '<li>Sensitive data pattern detected</li>';
    
    const recommendations = scanResult.recommendations && scanResult.recommendations.length > 0
      ? scanResult.recommendations.map(rec => `<li>${rec}</li>`).join('')
      : '<li>Verify the website is legitimate before proceeding</li>';

    content.innerHTML = `
      <h3 style="color: #f44336; margin-top: 0;">⚠️ Data Leak Warning</h3>
      <p>Sensitive data detected in form submission to:</p>
      <p style="font-weight: bold; color: #333; word-break: break-all;">${targetUrl}</p>
      <ul style="color: #666; margin: 10px 0;">
        ${sensitiveDataList}
      </ul>
      <p style="font-size: 14px; color: #666;">
        Recommendations:
        <ul style="margin: 10px 0;">
          ${recommendations}
        </ul>
      </p>
      <div style="text-align: right; margin-top: 20px;">
        <button id="block-btn" style="background: #f44336; color: white; border: none; padding: 10px 20px; margin-right: 10px; border-radius: 4px; cursor: pointer;">Block Submission</button>
        <button id="continue-btn" style="background: #4caf50; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer;">Continue Anyway</button>
      </div>
      <div style="position: absolute; top: 10px; right: 15px; font-size: 20px; cursor: pointer; color: #666;" id="close-btn">&times;</div>
    `;
    
    const blockBtn = content.querySelector('#block-btn');
    const continueBtn = content.querySelector('#continue-btn');
    const closeBtn = content.querySelector('#close-btn');
    
    const cleanup = () => {
      if (modal.parentElement) {
        modal.remove();
      }
    };
    
    blockBtn.onclick = (e) => {
      e.preventDefault();
      cleanup();
      callback(true); // Block submission
    };
    
    continueBtn.onclick = (e) => {
      e.preventDefault();
      cleanup();
      callback(false); // Allow submission
    };
    
    closeBtn.onclick = (e) => {
      e.preventDefault();
      cleanup();
      callback(true); // Block by default when closed
    };
    
    // Close on background click
    modal.onclick = (e) => {
      if (e.target === modal) {
        cleanup();
        callback(true); // Block by default
      }
    };
    
    modal.appendChild(content);
    return modal;
  }

  showInPageAlert(alert) {
    const alertEl = document.createElement('div');
    alertEl.className = 'secureguard-alert';
    alertEl.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${this.getAlertColor(alert.severity)};
      color: white;
      padding: 15px 20px;
      border-radius: 6px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      z-index: 10003;
      max-width: 350px;
      font-family: Arial, sans-serif;
      font-size: 14px;
      animation: slideIn 0.3s ease-out;
    `;
    
    alertEl.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <strong>${alert.type.replace('_', ' ').toUpperCase()}</strong>
          <p style="margin: 5px 0 0 0;">${alert.message}</p>
        </div>
        <button style="background: none; border: none; color: white; font-size: 18px; cursor: pointer; margin-left: 10px;">&times;</button>
      </div>
    `;
    
    // Add close functionality
    alertEl.querySelector('button').onclick = () => alertEl.remove();
    
    document.body.appendChild(alertEl);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (alertEl.parentElement) {
        alertEl.remove();
      }
    }, 5000);
    
    // Add slide-in animation
    if (!document.querySelector('#secureguard-styles')) {
      const style = document.createElement('style');
      style.id = 'secureguard-styles';
      style.textContent = `
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
      `;
      document.head.appendChild(style);
    }
  }

  getAlertColor(severity) {
    switch (severity) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#fbc02d';
      case 'low': return '#388e3c';
      default: return '#1976d2';
    }
  }

  async checkCurrentPageSecurity() {
    const url = window.location.href;
    const result = await chrome.runtime.sendMessage({
      type: 'SCAN_DATA',
      data: url
    });
    
    if (result && result.urlReputation && result.urlReputation.malicious) {
      this.showInPageAlert({
        type: 'malicious_site',
        message: 'Warning: This site may be malicious',
        severity: 'critical'
      });
    }
  }

  highlightRiskyElements() {
    this.sensitiveSelectors.forEach(selector => {
      document.querySelectorAll(selector).forEach(element => {
        this.highlightElement(element, 'warning');
      });
    });
  }
}

// Initialize the content script guard
const contentGuard = new ContentScriptGuard();