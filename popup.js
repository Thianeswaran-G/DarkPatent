class PopupController {
  constructor() {
    this.currentTab = 'dashboard';
    this.settings = {};
    this.alerts = [];
    this.stats = { sitesScanned: 0 };
    this.init();
  }

  async init() {
    await this.loadData();
    this.setupEventListeners();
    this.updateUI();
    this.startPeriodicUpdate();
  }

  async loadData() {
    try {
      const result = await chrome.storage.local.get(['settings', 'alerts', 'stats']);
      this.settings = result.settings || {
        realTimeScanning: true,
        darkWebScanning: true,
        autoBlock: false,
        notifications: true,
        alertLevel: 'medium',
      };
      this.alerts = result.alerts || [];
      this.stats = result.stats || { sitesScanned: 0 };
    } catch (e) {
      console.error('Error loading data:', e);
    }
  }

  setupEventListeners() {
    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => this.switchTab(tab.dataset.tab));
    });

    const scanBtn = document.getElementById('scanPageBtn');
    if (scanBtn) scanBtn.addEventListener('click', this.scanPage.bind(this));

    const clearBtn = document.getElementById('clearAlertsBtn');
    if (clearBtn) clearBtn.addEventListener('click', this.clearAlerts.bind(this));

    const exportBtn = document.getElementById('exportDataBtn');
    if (exportBtn) exportBtn.addEventListener('click', this.exportData.bind(this));

    const settingsBtn = document.getElementById('settingsBtn');
    if (settingsBtn) settingsBtn.addEventListener('click', () => this.switchTab('settings'));

    const breachBtn = document.getElementById('breachCheckBtn');
    if (breachBtn) breachBtn.addEventListener('click', this.checkBreaches.bind(this));

    document.querySelectorAll('.toggle-switch').forEach(toggle => {
      toggle.addEventListener('click', () => {
        const setting = toggle.dataset.setting;
        const enabled = toggle.classList.toggle('active');
        this.updateSetting(setting, enabled);
      });
    });

    const alertLevelSelect = document.getElementById('alertLevelSelect');
    if (alertLevelSelect) {
      alertLevelSelect.value = this.settings.alertLevel || 'medium';
      alertLevelSelect.addEventListener('change', e => this.updateSetting('alertLevel', e.target.value));
    }

    const resetBtn = document.getElementById('resetSettingsBtn');
    if (resetBtn) resetBtn.addEventListener('click', this.resetSettings.bind(this));
  }

  switchTab(tabName) {
    this.currentTab = tabName;
    document.querySelectorAll('.tab').forEach(tab => {
      tab.classList.toggle('active', tab.dataset.tab === tabName);
    });
    document.querySelectorAll('.tab-content').forEach(content => {
      content.classList.toggle('active', content.id === tabName);
    });
    if (tabName === 'alerts') this.renderAlerts();
  }

  updateUI() {
    const protectionStatus = document.getElementById('protectionStatus');
    if (protectionStatus) {
      protectionStatus.textContent = this.settings.realTimeScanning ? 'ACTIVE' : 'DISABLED';
      protectionStatus.style.color = this.settings.realTimeScanning ? '#4CAF50' : '#f44336';
    }

    const alertCount = document.getElementById('alertCount');
    if (alertCount) alertCount.textContent = this.alerts.length;

    const sitesScanned = document.getElementById('sitesScanned');
    if (sitesScanned) sitesScanned.textContent = this.stats.sitesScanned;

    document.querySelectorAll('.toggle-switch').forEach(toggle => {
      const setting = toggle.dataset.setting;
      if (this.settings[setting]) {
        toggle.classList.add('active');
      } else {
        toggle.classList.remove('active');
      }
    });

    const alertLevelSelect = document.getElementById('alertLevelSelect');
    if (alertLevelSelect) alertLevelSelect.value = this.settings.alertLevel || 'medium';
  }

  renderAlerts() {
    const container = document.getElementById('alertsList');
    if (!container) return;

    if (this.alerts.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-icon">🔒</div>No alerts</div>';
      return;
    }
    
    container.innerHTML = this.alerts.map(alert => `
      <div class="alert-item">
        <strong>${this.formatAlertType(alert.type)}</strong> - ${this.formatTime(alert.timestamp)}<br />
        ${this.formatAlertMessage(alert)}
        <button class="dismissBtn" data-id="${alert.id}">Dismiss</button>
      </div>`).join('');
    
    container.querySelectorAll('.dismissBtn').forEach(btn =>
      btn.addEventListener('click', e => this.dismissAlert(e.target.dataset.id))
    );
  }

  formatAlertType(type) {
    return type.replace(/_/g, ' ').toUpperCase();
  }

  formatTime(ts) {
    const diff = (Date.now() - ts) / 1000;
    if (diff < 60) return `${Math.floor(diff)} seconds ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
    return `${Math.floor(diff / 86400)} days ago`;
  }

  formatAlertMessage(alert) {
    switch (alert.type) {
      case 'data_transmission':
        return `Sensitive data detected on ${new URL(alert.url).hostname}`;
      case 'header_leak':
        return `Potential header leak on ${new URL(alert.url).hostname}`;
      case 'breach_detected':
        return `Email found in ${alert.count} breach(es).`;
      default:
        return alert.message || 'Security alert detected.';
    }
  }

  async dismissAlert(id) {
    this.alerts = this.alerts.filter(a => a.id != id);
    await chrome.storage.local.set({ alerts: this.alerts });
    try {
      await chrome.runtime.sendMessage({ type: 'CLEAR_ALERT', alertId: id });
    } catch (e) {
      console.warn('Clear alert message failed:', e);
    }
    this.renderAlerts();
    this.updateUI();
  }

  async scanPage() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id) {
        alert("No valid web page is active for scanning.");
        return;
      }
      if (!tab.url.startsWith("http")) {
        alert("Scanning works only on normal web pages.");
        return;
      }
      const response = await chrome.tabs.sendMessage(tab.id, { type: 'SCAN_PAGE' });
      console.log('Scan message response:', response);
    } catch (e) {
      console.error('Error sending scan message:', e);
      alert("Failed to scan: content script not reachable.");
    }
  }

  async clearAlerts() {
    this.alerts = [];
    await chrome.storage.local.set({ alerts: [] });
    try {
      await chrome.runtime.sendMessage({ type: 'CLEAR_ALL_ALERTS' });
    } catch (e) {
      console.warn('Clear all alerts message failed:', e);
    }
    this.renderAlerts();
    this.updateUI();
  }

  async exportData() {
    try {
      const data = JSON.stringify({
        alerts: this.alerts,
        settings: this.settings,
        exportedAt: new Date().toISOString()
      }, null, 2);

      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      await chrome.downloads.download({
        url,
        filename: `secureguard_export_${Date.now()}.json`,
        saveAs: true
      });
    } catch (e) {
      console.error('Error exporting data:', e);
    }
  }

  async checkBreaches() {
    const emailInput = document.getElementById('breachEmail');
    if (!emailInput) {
      alert("Internal error: email input not found.");
      return;
    }
    const email = emailInput.value.trim();
    if (!email || !email.includes('@')) {
      alert("Please enter a valid email address.");
      return;
    }
    try {
      const response = await chrome.runtime.sendMessage({ type: 'CHECK_BREACH', email });
      const breachResult = document.getElementById('breachResult');
      if (response?.error) {
        breachResult.textContent = 'Error checking breach.';
        breachResult.style.color = '#f44336';
      } else if (response?.breached) {
        const names = response.breaches.map(b => b.Name).join(', ');
        breachResult.textContent = `Found in breaches: ${names}`;
        breachResult.style.color = '#f44336';
      } else {
        breachResult.textContent = 'No breaches found.';
        breachResult.style.color = '#4CAF50';
      }
    } catch (e) {
      alert("Error checking breach status.");
      console.error("Check breach error:", e);
    }
  }

  async updateSetting(key, value) {
    this.settings[key] = value;
    await chrome.storage.local.set({ settings: this.settings });
    try {
      await chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', settings: this.settings });
    } catch (e) {
      console.warn("Update settings message failed:", e);
    }
    this.updateUI();
  }

  async resetSettings() {
    this.settings = {
      realTimeScanning: true,
      darkWebScanning: true,
      autoBlock: false,
      notifications: true,
      alertLevel: 'medium'
    };
    await chrome.storage.local.set({ settings: this.settings });
    try {
      await chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', settings: this.settings });
    } catch (e) {
      console.warn("Reset settings message failed:", e);
    }
    this.updateUI();
  }

  startPeriodicUpdate() {
    setInterval(async () => {
      await this.loadData();
      this.updateUI();
      if (this.currentTab === 'alerts') this.renderAlerts();
    }, 5000);
  }
}

let popup;

document.addEventListener('DOMContentLoaded', () => {
  popup = new PopupController();
});
