class SecurityEngine {
  constructor() {
    this.breachAPIs = {
      haveibeened: 'https://haveibeened.com/api/v3',
      phishtank: 'https://checkurl.phishtank.com'
    };

    this.sensitivePatterns = [
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // Credit card
      /\b\d{3}-?\d{2}-?\d{4}\b/,                    // SSN
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, // Email
      /\b(?:\d{1,3}\.){3}\d{1,3}\b/,                // IP address
      /\bpassword\s*[:=]\s*\S+/i,                   // Password
      /\bapi[_-]?key\s*[:=]\s*\S+/i                 // API Key
    ];

    this.userSettings = {};
    this.alertQueue = [];
    this.whitelistedSites = new Set();

    this.init();
  }

  async init() {
    const stored = await chrome.storage.local.get(['settings', 'whitelist']);
    this.userSettings = stored.settings || {
      realTimeScanning: true,
      darkWebScanning: true,
      alertLevel: 'medium',
      autoBlock: false
    };
    this.whitelistedSites = new Set(stored.whitelist || []);
    this.setupRequestListener();
    this.setupMessageListener();
    this.schedulePeriodicScans();
  }

  setupRequestListener() {
    chrome.webRequest.onBeforeRequest.addListener(
      this.analyzeRequest.bind(this),
      { urls: ['<all_urls>'] },
      ['requestBody']
    );
    chrome.webRequest.onBeforeSendHeaders.addListener(
      this.analyzeHeaders.bind(this),
      { urls: ['<all_urls>'] },
      ['requestHeaders']
    );
  }

  setupMessageListener() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      switch (message.type) {
        case 'SCAN_DATA':
          this.scanDataForLeaks(message.data, sender.tab?.url).then(result => sendResponse(result));
          return true; // Keep message channel open for async response
        case 'CHECK_BREACH':
          this.checkDataBreach(message.email).then(result => sendResponse(result));
          return true;
        case 'UPDATE_SETTINGS':
          this.updateSettings(message.settings).then(() => sendResponse({ success: true }));
          return true;
        case 'GET_ALERTS':
          sendResponse(this.alertQueue);
          break;
        case 'CLEAR_ALERT':
          this.clearAlert(message.alertId).then(() => sendResponse({ success: true }));
          return true;
      }
    });
  }

  async analyzeRequest(details) {
    if (!this.userSettings.realTimeScanning) return;
    try {
      const urlObj = new URL(details.url);
      if (this.whitelistedSites.has(urlObj.hostname)) return;

      if (details.requestBody) {
        const data = this.extractFormData(details.requestBody);
        const leaks = this.detectSensitiveData(data);
        if (leaks.length) {
          await this.createAlert({
            type: 'data_transmission',
            severity: 'high',
            url: details.url,
            data: leaks,
            timestamp: Date.now(),
            tabId: details.tabId
          });
        }
      }
    } catch (e) {
      console.error('Error analyzing request:', e);
    }
  }

  async analyzeHeaders(details) {
    try {
      const suspiciousHeaders = ['x-api-key', 'authorization', 'x-auth-token'];
      for (const header of details.requestHeaders || []) {
        if (suspiciousHeaders.some(h => header.name.toLowerCase().includes(h))) {
          const leaks = this.detectSensitiveData(header.value);
          if (leaks.length) {
            await this.createAlert({
              type: 'header_leak',
              severity: 'medium',
              url: details.url,
              header: header.name,
              timestamp: Date.now(),
              tabId: details.tabId
            });
          }
        }
      }
    } catch (e) {
      console.error('Error analyzing headers:', e);
    }
  }

  extractFormData(requestBody) {
    let data = '';
    if (requestBody.formData) {
      for (const [key, values] of Object.entries(requestBody.formData)) {
        data += `${key}: ${values.join(', ')} `;
      }
    }
    if (requestBody.raw) {
      for (const item of requestBody.raw) {
        if (item.bytes) {
          data += new TextDecoder().decode(new Uint8Array(item.bytes));
        }
      }
    }
    return data;
  }

  detectSensitiveData(text) {
    const found = [];
    for (const [i, pattern] of this.sensitivePatterns.entries()) {
      const matches = text.match(pattern);
      if (matches) {
        found.push({ type: this.getPatternType(i), value: matches[0], pattern: pattern.toString() });
      }
    }
    return found;
  }

  getPatternType(index) {
    const types = ['credit_card', 'ssn', 'email', 'ip_address', 'password', 'api_key'];
    return types[index] || 'unknown';
  }

  async scanDataForLeaks(data, url) {
    const leaks = this.detectSensitiveData(data);
    const reputation = await this.checkUrlReputation(url);
    const recommendations = [];

    if (leaks.length) recommendations.push('Sensitive data detected.');
    if (reputation?.malicious) recommendations.push('Warning: Potentially malicious site.');

    return { sensitiveData: leaks, reputation, recommendations };
  }

  async checkDataBreach(email) {
    if (!this.userSettings.darkWebScanning) return { checked: false, reason: 'Disabled' };
    try {
      const res = await fetch(`${this.breachAPIs.haveibeened}/breachedaccount/${email}`, {
        method: 'GET',
        headers: { 'hibp-api-key': 'YOUR_API_KEY', 'User-Agent': 'SecureGuard' }
      });
      if (res.status === 200) {
        const data = await res.json();
        return { breached: true, breaches: data, count: data.length };
      } else if (res.status === 404) {
        return { breached: false, message: 'No breaches found' };
      }
    } catch (e) {
      console.error(e);
      return { error: true, message: 'API error' };
    }
  }

  async checkUrlReputation(url) {
    try {
      const res = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_GOOGLE_API_KEY', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'secureguard', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      });
      const data = await res.json();
      return { malicious: Array.isArray(data.matches) && data.matches.length > 0, threats: data.matches || [] };
    } catch (e) {
      console.error(e);
      return { error: true };
    }
  }

  async createAlert(alert) {
    alert.id = Date.now() + Math.random();
    this.alertQueue.push(alert);
    await chrome.storage.local.set({ alerts: this.alertQueue });
    chrome.notifications.create(alert.id.toString(), {
      title: 'SecureGuard Alert',
      message: this.formatAlertMessage(alert),
      iconUrl: 'icons/icon48.png',
      type: 'basic'
    });
    chrome.action.setBadgeText({ text: this.alertQueue.length.toString() });
    chrome.action.setBadgeBackgroundColor({ color: '#ff4444' });
  }

  formatAlertMessage(alert) {
    switch (alert.type) {
      case 'data_transmission': return `Sensitive data sent to ${new URL(alert.url).hostname}`;
      case 'header_leak': return `Potential header leak on ${new URL(alert.url).hostname}`;
      case 'breach_detected': return `Email found in ${alert.count} breaches`;
      default: return 'Security alert detected';
    }
  }

  async clearAlert(id) {
    this.alertQueue = this.alertQueue.filter(alert => alert.id !== id);
    await chrome.storage.local.set({ alerts: this.alertQueue });
    chrome.action.setBadgeText({ text: this.alertQueue.length ? this.alertQueue.length.toString() : '' });
  }

  async updateSettings(settings) {
    this.userSettings = { ...this.userSettings, ...settings };
    await chrome.storage.local.set({ settings: this.userSettings });
  }

  schedulePeriodicScans() {
    setInterval(async () => {
      if (!this.userSettings.darkWebScanning) return;
      const { watchedEmails = [] } = await chrome.storage.local.get('watchedEmails');
      for (const email of watchedEmails) {
        const res = await this.checkDataBreach(email);
        if (res.breached && res.count > 0) {
          await this.createAlert({
            type: 'breach_detected',
            severity: 'critical',
            email,
            count: res.count,
            timestamp: Date.now()
          });
        }
      }
    }, 86400000); // every 24 hours
  }
}

// Initialize engine
const securityEngine = new SecurityEngine();
