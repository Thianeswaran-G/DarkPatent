class ContentScriptGuard {
  constructor() {
    this.sensitiveSelectors = [
      'input[type=password]',
      'input[type=email]',
      'input[name*=ssn]',
      'input[name*=social]',
      'input[name*=credit]',
      'input[name*=card]',
      'input[name*=cvv]',
      'input[name*=api]',
      'textarea'
    ];

    this.monitoredElements = new Set();
    this.currentAlerts = [];
    this.handleFormSubmissionBound = this.handleFormSubmission.bind(this);

    window.contentGuard = this;
    this.init();
  }

  init() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.setupMonitoring());
    } else {
      this.setupMonitoring();
    }
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'SCAN_PAGE') {
        this.runPageScan();
        sendResponse({ status: 'scan_started' });
        return true;
      }
      switch (message.type) {
        case 'SHOW_ALERT':
          this.showInPageAlert(message.alert);
          break;
        case 'BLOCK_SUBMISSION':
          this.blockFormSubmission && this.blockFormSubmission(message.reason);
          break;
        case 'HIGHLIGHT_RISKS':
          this.highlightRiskyElements();
          break;
      }
    });
  }

  setupMonitoring() {
    document.addEventListener('submit', this.handleFormSubmissionBound, true);
    document.addEventListener('input', this.handleInputChange.bind(this), true);
    document.addEventListener('paste', this.handlePaste.bind(this), true);
    document.addEventListener('copy', this.handleCopy.bind(this), true);
    document.addEventListener('change', this.handleAutofill.bind(this), true);

    this.setupMutationObserver();
    this.scanExistingElements();
    this.checkCurrentSecurity && this.checkCurrentSecurity();
  }

  async handleFormSubmission(event) {
  const form = event.target;
  if (!form || form.tagName !== 'FORM') return;

  event.preventDefault();

  const formData = new FormData(form);
  const dataString = Array.from(formData.entries())
    .map(([key, value]) => `${key}: ${value}`)
    .join(' ');

  try {
    const result = await chrome.runtime.sendMessage({
      type: 'SCAN_DATA',
      data: dataString
    });

    if (result && result.sensitiveData && result.sensitiveData.length > 0) {
      const shouldBlock = await this.showSubmissionWarning(result, form.action || window.location.href);
      if (shouldBlock) {
        // Show visual feedback for blocking
        let toast = document.createElement('div');
        toast.textContent = "Submission blocked for your safety.";
        toast.style.cssText = `
          position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%);
          background: #d32f2f; color: white; padding: 12px 32px; border-radius: 5px;
          z-index: 100002; font-size: 18px; box-shadow: 0 2px 8px #0006;
        `;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
        // Stay on page, do not submit
        return;
      } else {
        form.removeEventListener('submit', this.handleFormSubmissionBound, true);
        form.submit();
      }
    } else {
      form.removeEventListener('submit', this.handleFormSubmissionBound, true);
      form.submit();
    }
  } catch (e) {
    form.removeEventListener('submit', this.handleFormSubmissionBound, true);
    form.submit();
  }
}


  handleInputChange(event) {
    const input = event.target;
    if (!this.isSensitiveInput(input) || input.value.length < 10) return;
    chrome.runtime.sendMessage({ type: 'SCAN_DATA', data: input.value }).then(result => {
      if (result && result.sensitiveData && result.sensitiveData.length > 0) {
        this.highlightElement(input, 'warning');
        this.showTooltip(input, 'Sensitive data detected');
      }
    });
  }

  handlePaste(event) {
    const pastedText = event.clipboardData?.getData('text') || '';
    if (!pastedText) return;
    chrome.runtime.sendMessage({ type: 'SCAN_DATA', data: pastedText }).then(result => {
      if (result && result.sensitiveData && result.sensitiveData.length > 0) {
        this.showInPageAlert({
          type: 'paste_warning',
          message: 'Sensitive data detected in pasted text',
          severity: 'medium',
          data: result.sensitiveData
        });
      }
    });
  }

  handleCopy(event) {
    const selection = window.getSelection().toString();
    if (selection.length < 10) return;
    chrome.runtime.sendMessage({ type: 'SCAN_DATA', data: selection }).then(result => {
      if (result && result.sensitiveData && result.sensitiveData.length > 0) {
        this.showInPageAlert({
          type: 'copy_warning',
          message: 'Sensitive data detected in copied text',
          severity: 'low',
          data: result.sensitiveData
        });
      }
    });
  }

  handleAutofill(event) {
    const input = event.target;
    if (input.tagName !== 'INPUT' || !event.isTrusted) return;
    setTimeout(() => {
      chrome.runtime.sendMessage({ type: 'SCAN_DATA', data: input.value }).then(result => {
        if (result && result.sensitiveData && result.sensitiveData.length > 0) {
          this.showTooltip(input, 'Sensitive data detected (autofilled)');
        }
      });
    }, 100);
  }

  setupMutationObserver() {
    const observer = new MutationObserver(mutations => {
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === 1) this.scanNewElement(node);
        });
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  scanExistingElements() {
    this.sensitiveSelectors.forEach(sel => {
      document.querySelectorAll(sel).forEach(el => this.monitorElement(el));
    });
  }

  scanNewElement(node) {
    this.sensitiveSelectors.forEach(sel => {
      if (node.matches && node.matches(sel)) this.monitorElement(node);
      node.querySelectorAll && node.querySelectorAll(sel).forEach(el => this.monitorElement(el));
    });
  }

  monitorElement(el) {
    if (this.monitoredElements.has(el)) return;
    this.monitoredElements.add(el);
    this.addIndicator(el);
  }

  isSensitiveInput(el) {
    const sensitiveTypes = ['password', 'email'];
    const sensitiveNames = ['ssn', 'social', 'credit', 'card', 'cvv', 'api'];
    return sensitiveTypes.includes(el.type) || sensitiveNames.some(name =>
      (el.name && el.name.toLowerCase().includes(name)) ||
      (el.id && el.id.toLowerCase().includes(name)) ||
      (el.className && el.className.toLowerCase().includes(name))
    );
  }

  addIndicator(el) {
    const indicator = document.createElement('div');
    indicator.className = 'secureguard-indicator';
    indicator.textContent = '🛡️';
    indicator.style.cssText = `
      position: absolute;
      right: 5px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 12px;
      opacity: 0.6;
      pointer-events: none;
      z-index: 9999;
    `;
    const parent = el.parentElement;
    if (parent && getComputedStyle(parent).position === 'static') {
      parent.style.position = 'relative';
    }
    parent?.appendChild(indicator);
  }

  highlightElement(el, type) {
    const color = type === 'warning' ? '#FFC107' : '#F44336';
    el.style.border = `2px solid ${color}`;
    el.style.boxShadow = `0 0 8px ${color}aa`;
  }

  showTooltip(el, msg) {
    const tooltip = document.createElement('div');
    tooltip.className = 'secureguard-tooltip';
    tooltip.textContent = msg;
    tooltip.style.cssText = `
      position: absolute;
      background: #333;
      color: white;
      padding: 5px 10px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 10001;
    `;
    document.body.appendChild(tooltip);
    const rect = el.getBoundingClientRect();
    tooltip.style.left = `${rect.left}px`;
    tooltip.style.top = `${rect.bottom + 5}px`;
    setTimeout(() => tooltip.remove(), 3000);
  }

  async showSubmissionWarning(scanResult, formAction) {
    return new Promise(resolve => {
      const modal = this.createWarningModal(scanResult, formAction, resolve);
      document.body.appendChild(modal);
      // Modal will be removed only on user action
    });
  }

  createWarningModal(scanResult, formAction, resolve) {
    document.querySelectorAll('.secureguard-modal').forEach(m => m.remove());
    const modal = document.createElement('div');
    modal.className = 'secureguard-modal';
    modal.style.cssText = `
      position: fixed;
      top: 0; left: 0;
      width: 100vw; height: 100vh;
      background: rgba(0,0,0,0.8);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 100000;
      font-family: Arial, sans-serif;
    `;

    const content = document.createElement('div');
    content.style.cssText = `
      background: white;
      border-radius: 8px;
      padding: 20px;
      max-width: 400px;
      max-height: 80vh;
      overflow-y: auto;
      position: relative;
    `;

    const dataList = scanResult.sensitiveData?.map(d => `<li>${d.type}: ${d.value}</li>`).join('') || '<li>Detected sensitive data.</li>';
    const recList = scanResult.recommendations?.map(r => `<li>${r}</li>`).join('') || '<li>Please review before proceeding.</li>';

    content.innerHTML = `
      <h2 style="color:#d32f2f;">⚠️ Potential Data Leak Detected</h2>
      <p><strong>Form action:</strong> ${formAction}</p>
      <p><strong>Detected sensitive data:</strong></p>
      <ul>${dataList}</ul>
      <p><strong>Recommendations:</strong></p>
      <ul>${recList}</ul>
      <div style="margin-top:20px; text-align:right;">
        <button id="blockBtn" style="background:#d32f2f; color:white; margin-right:10px; padding:10px 20px; border:none; border-radius:4px; cursor:pointer;">Block Submission</button>
        <button id="continueBtn" style="background:#4caf50; color:white; padding:10px 20px; border:none; border-radius:4px; cursor:pointer;">Continue Anyway</button>
      </div>
      <button id="closeBtn" style="position:absolute; top:10px; right:10px; background:none; border:none; font-size:24px; cursor:pointer;">&times;</button>
    `;

    content.querySelector('#blockBtn').onclick = () => {
      modal.remove();
      resolve(true);
    };
    content.querySelector('#continueBtn').onclick = () => {
      modal.remove();
      resolve(false);
    };
    content.querySelector('#closeBtn').onclick = () => {
      modal.remove();
      resolve(true);
    };
    modal.onclick = e => {
      if (e.target === modal) {
        modal.remove();
        resolve(true);
      }
    };
    modal.appendChild(content);
    return modal;
  }

  async runPageScan() {
    let combinedData = '';
    this.sensitiveSelectors.forEach(selector => {
      document.querySelectorAll(selector).forEach(el => {
        combinedData += el.value + ' ';
      });
    });
    const result = await chrome.runtime.sendMessage({ type: 'SCAN_DATA', data: combinedData });
    if (result && result.sensitiveData && result.sensitiveData.length > 0) {
      this.showInPageAlert({
        type: 'scan_result',
        message: 'Sensitive data detected on this page',
        severity: 'high',
        data: result.sensitiveData
      });
    }
  }

  showInPageAlert(alert) {
    // Optional: Implement as toast/banner if desired
    console.log('In-page alert:', alert);
  }
}

const contentGuard = new ContentScriptGuard();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_PAGE') {
    contentGuard.runPageScan();
    sendResponse({ status: 'scan_started' });
    return true;
  }
});
