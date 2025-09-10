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

    document.getElementById('scanPageBtn').addEventListener('click', this.scanPage.bind(this));
    document.getElementById('clearAlertsBtn').addEventListener('click', this.clearAlerts.bind(this));
    document.getElementById('exportDataBtn').addEventListener('click', this.exportData.bind(this));
    document.getElementById('settingsBtn').addEventListener('click', () => this.switchTab('settings'));
    document.getElementById('breachCheckBtn').addEventListener('click', this.checkBreaches.bind(this));

    document.querySelectorAll('.toggle-switch').forEach(toggle => {
      toggle.addEventListener('click', e => {
        const setting = toggle.dataset.setting;
        const enabled = toggle.classList.toggle('active');
        this.updateSetting(setting, enabled);
      });
    });

    document.getElementById('alertLevelSelect').addEventListener('change', e => {
      this.updateSetting('alertLevel', e.target.value);
    });

    document.getElementById('resetSettingsBtn').addEventListener('click', this.resetSettings.bind(this));
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
    document.getElementById('protectionStatus').textContent = this.settings.realTimeScanning ? 'ACTIVE' : 'DISABLED';
    document.getElementById('protectionStatus').style.color = this.settings.realTimeScanning ? '#4CAF50' : '#f44336';
    document.getElementById('alertCount').textContent = this.alerts.length;
    document.getElementById('sitesScanned').textContent = this.stats.sitesScanned;
    document.getElementById('alertLevelSelect').value = this.settings.alertLevel;

    document.querySelectorAll('.toggle-switch').forEach(toggle => {
      const setting = toggle.dataset.setting;
      toggle.classList.toggle('active', !!this.settings[setting]);
    });
  }

  async updateSetting(key, value) {
    this.settings[key] = value;
    await chrome.storage.local.set({ settings: this.settings });
    chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', settings: this.settings });
    this.updateUI();
  }

  renderAlerts() {
    const container = document.getElementById('alertsList');
    if (this.alerts.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-icon">🔒</div>No alerts</div>';
      return;
    }
    container.innerHTML = this.alerts.map(alert => `
      <div class="alert-item">
        <strong>${this.formatAlertType(alert.type)}</strong> - ${this.formatTime(alert.timestamp)}<br>
        ${this.formatAlertMessage(alert)}
        <button class="dismissBtn" data-id="${alert.id}">Dismiss</button>
      </div>
    `).join('');
    container.querySelectorAll('.dismissBtn').forEach(btn => {
      btn.addEventListener('click', e => this.dismissAlert(e.target.dataset.id));
    });
  }

  formatAlertType(type) {
    return type.replace('_', ' ').toUpperCase();
  }

  formatTime(ts) {
    const diff = (Date.now() - ts) / 1000;
    if (diff < 60) return `${Math.floor(diff)} sec ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)} hr ago`;
    return `${Math.floor(diff / 86400)} day(s) ago`;
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
        return 'Security alert';
    }
  }

  async dismissAlert(id) {
    this.alerts = this.alerts.filter(a => a.id != id);
    await chrome.storage.local.set({ alerts: this.alerts });
    chrome.runtime.sendMessage({ type: 'CLEAR_ALERT', alertId: id });
    this.renderAlerts();
    this.updateUI();
  }

  async scanPage() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    chrome.tabs.sendMessage(tab.id, { type: 'SCAN_PAGE' });
  }

  async clearAlerts() {
    this.alerts = [];
    await chrome.storage.local.set({ alerts: [] });
    chrome.runtime.sendMessage({ type: 'CLEAR_ALL_ALERTS' });
    this.renderAlerts();
    this.updateUI();
  }

  async exportData() {
    const data = JSON.stringify({
      alerts: this.alerts,
      settings: this.settings,
      exportedAt: new Date().toISOString()
    }, null, 2);

    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    chrome.downloads.download({
      url, filename: `secureguard_data_${Date.now()}.json`
    });
  }

  async checkBreaches() {
    const email = document.getElementById('breachEmail').value;
    if (!email) {
      this.showBreachResult('Enter a valid email address.');
      return;
    }

    this.showBreachResult('Checking...');
    try {
      const response = await chrome.runtime.sendMessage({ type: 'CHECK_BREACH', email });
      if (response.error) {
        this.showBreachResult('Error checking breaches.');
      } else if (response.breached) {
        this.showBreachResult(`Found in ${response.count} breaches: ${response.breaches.map(b => b.Name).join(', ')}`, true);
      } else {
        this.showBreachResult('No breaches found.', false);
      }
    } catch {
      this.showBreachResult('Error checking breaches.');
    }
  }

  showBreachResult(msg, isWarning) {
    const container = document.getElementById('breachResult');
    container.textContent = msg;
    container.style.color = isWarning ? '#f44336' : '#4CAF50';
  }

  async resetSettings() {
    this.settings = {
      realTimeScanning: true,
      darkWebScanning: true,
      autoBlock: false,
      notifications: true,
      alertLevel: 'medium',
    };
    await chrome.storage.local.set({ settings: this.settings });
    chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', settings: this.settings });
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

  // Expose global functions if needed by onclick in HTML (avoid if possible)
  window.scanPage = () => popup.scanPage();
  window.clearAlerts = () => popup.clearAlerts();
  window.exportData = () => popup.exportData();
  window.openSettings = () => popup.switchTab('settings');
  window.checkBreaches = () => popup.checkBreaches();
});
