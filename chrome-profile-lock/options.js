/**
 * Chrome Profile Lock - Advanced Security Options Controller
 *
 * Implements:
 * - Chrome System Idle Detection (chrome.idle API)
 * - Security Status Card (live telemetry)
 * - Protected Security Settings (authentication required guard)
 * - Change Password & Change PIN Modals
 * - Secure Authentication Mode Switching (requires current credentials)
 * - Standardized Security Activity Logging (latest 5 events with icons)
 * - Danger Zone Reset Security Settings (authenticated confirmation)
 * - Pure Web Crypto API (PBKDF2-HMAC-SHA256, 310,000 iterations, 16-byte random salt)
 * - Dual Storage Schema (structured authCredential + legacy keys for 100% backward compatibility)
 */

document.addEventListener('DOMContentLoaded', async () => {
  const PBKDF2_ITERATIONS = 310000;
  const HASH_BITS = 256;

  // ---------------------------------------------------------------------------
  // DOM Elements
  // ---------------------------------------------------------------------------

  // Header & Metrics
  const lockNowBtn = document.getElementById('lockNowBtn');
  const metricTotalLocks = document.getElementById('metricTotalLocks');
  const metricTotalUnlocks = document.getElementById('metricTotalUnlocks');
  const metricBlockedIntrusions = document.getElementById('metricBlockedIntrusions');
  const metricLastActive = document.getElementById('metricLastActive');

  // Profile Section
  const profileNameForm = document.getElementById('profileNameForm');
  const profileNameInput = document.getElementById('profileNameInput');
  const profileEmailInput = document.getElementById('profileEmailInput');
  const avatarPickerGrid = document.getElementById('avatarPickerGrid');
  let selectedAvatar = 'monogram';

  // Security Status Card
  const statusProfileProtection = document.getElementById('statusProfileProtection');
  const statusAuthMode = document.getElementById('statusAuthMode');
  const statusIdleLock = document.getElementById('statusIdleLock');
  const statusStartupLock = document.getElementById('statusStartupLock');
  const statusAutoMute = document.getElementById('statusAutoMute');
  const statusLastEvent = document.getElementById('statusLastEvent');

  // Credentials & Auth Mode
  const openChangePasswordModalBtn = document.getElementById('openChangePasswordModalBtn');
  const openChangePinModalBtn = document.getElementById('openChangePinModalBtn');
  const authModePasswordRadio = document.getElementById('authModePasswordRadio');
  const authModePinRadio = document.getElementById('authModePinRadio');
  const protectSecuritySettingsToggle = document.getElementById('protectSecuritySettingsToggle');
  const lockOnStartupToggle = document.getElementById('lockOnStartupToggle');

  // Automatic Lock (Unified Idle Lock)
  const systemIdleLockToggle = document.getElementById('systemIdleLockToggle');
  const systemIdleTimeoutSelect = document.getElementById('systemIdleTimeoutSelect');
  const idleStatusText = document.getElementById('idleStatusText');

  // Privacy
  const lockMuteAudioToggle = document.getElementById('lockMuteAudioToggle');
  const lockCloakTitleToggle = document.getElementById('lockCloakTitleToggle');
  const lockWarningToggle = document.getElementById('lockWarningToggle');
  const enableContextMenuLockToggle = document.getElementById('enableContextMenuLockToggle');

  // Themes
  const themePickerGrid = document.getElementById('themePickerGrid');

  // Security Activity Audit Log
  const activityList = document.getElementById('activityList');
  const clearLogsBtn = document.getElementById('clearLogsBtn');

  // Danger Zone
  const openResetSecurityModalBtn = document.getElementById('openResetSecurityModalBtn');

  // Global Toast
  const toastBox = document.getElementById('toastBox');

  // Modals
  // 1. Change Password Modal
  const changePasswordModal = document.getElementById('changePasswordModal');
  const closePasswordModalX = document.getElementById('closePasswordModalX');
  const closePasswordModalBtn = document.getElementById('closePasswordModalBtn');
  const changePasswordModalForm = document.getElementById('changePasswordModalForm');
  const modalCurrentPassword = document.getElementById('modalCurrentPassword');
  const modalNewPassword = document.getElementById('modalNewPassword');
  const modalConfirmPassword = document.getElementById('modalConfirmPassword');
  const modalPasswordAlert = document.getElementById('modalPasswordAlert');
  const submitChangePasswordBtn = document.getElementById('submitChangePasswordBtn');

  // 2. Change PIN Modal
  const changePinModal = document.getElementById('changePinModal');
  const closePinModalX = document.getElementById('closePinModalX');
  const closePinModalBtn = document.getElementById('closePinModalBtn');
  const changePinModalForm = document.getElementById('changePinModalForm');
  const modalCurrentPin = document.getElementById('modalCurrentPin');
  const modalNewPin = document.getElementById('modalNewPin');
  const modalConfirmPin = document.getElementById('modalConfirmPin');
  const modalPinAlert = document.getElementById('modalPinAlert');
  const submitChangePinBtn = document.getElementById('submitChangePinBtn');

  // 3. Switch Mode Modal
  const switchAuthModeModal = document.getElementById('switchAuthModeModal');
  const closeSwitchModeModalX = document.getElementById('closeSwitchModeModalX');
  const closeSwitchModeModalBtn = document.getElementById('closeSwitchModeModalBtn');
  const switchAuthModeForm = document.getElementById('switchAuthModeForm');
  const switchModeCurrentCred = document.getElementById('switchModeCurrentCred');
  const switchModeCurrentLabel = document.getElementById('switchModeCurrentLabel');
  const switchToPinWrap = document.getElementById('switchToPinWrap');
  const switchToPinNew = document.getElementById('switchToPinNew');
  const switchToPinConfirm = document.getElementById('switchToPinConfirm');
  const switchToPasswordWrap = document.getElementById('switchToPasswordWrap');
  const switchToPasswordNew = document.getElementById('switchToPasswordNew');
  const switchToPasswordConfirm = document.getElementById('switchToPasswordConfirm');
  const switchModeAlert = document.getElementById('switchModeAlert');
  const confirmSwitchModeBtn = document.getElementById('confirmSwitchModeBtn');
  let targetSwitchMode = 'password';

  // 4. Verify Modal
  const securityVerifyModal = document.getElementById('securityVerifyModal');
  const closeVerifyModalX = document.getElementById('closeVerifyModalX');
  const closeVerifyModalBtn = document.getElementById('closeVerifyModalBtn');
  const securityVerifyForm = document.getElementById('securityVerifyForm');
  const verifyCredentialInput = document.getElementById('verifyCredentialInput');
  const verifyModalAlert = document.getElementById('verifyModalAlert');
  const confirmVerifyBtn = document.getElementById('confirmVerifyBtn');
  let pendingProtectedAction = null;
  let pendingRevertElement = null;

  // 5. Reset Security Modal
  const resetSecurityModal = document.getElementById('resetSecurityModal');
  const closeResetModalX = document.getElementById('closeResetModalX');
  const closeResetModalBtn = document.getElementById('closeResetModalBtn');
  const resetSecurityForm = document.getElementById('resetSecurityForm');
  const resetCredentialInput = document.getElementById('resetCredentialInput');
  const resetModalAlert = document.getElementById('resetModalAlert');
  const confirmResetSecurityBtn = document.getElementById('confirmResetSecurityBtn');

  // 6. Backend API Configuration
  const backendApiUrlInput = document.getElementById('backendApiUrlInput');
  const saveBackendUrlBtn = document.getElementById('saveBackendUrlBtn');
  const testBackendBtn = document.getElementById('testBackendBtn');

  // 7. Security Alert Email Elements
  const detectedProfileEmailWrap = document.getElementById('detectedProfileEmailWrap');
  const detectedProfileEmailText = document.getElementById('detectedProfileEmailText');
  const manualSecurityEmailWrap = document.getElementById('manualSecurityEmailWrap');
  const securityEmailVerifiedStatus = document.getElementById('securityEmailVerifiedStatus');
  const verifiedSecurityEmailLabel = document.getElementById('verifiedSecurityEmailLabel');
  const changeSecurityEmailBtn = document.getElementById('changeSecurityEmailBtn');
  const securityEmailInputGroup = document.getElementById('securityEmailInputGroup');
  const securityEmailInput = document.getElementById('securityEmailInput');
  const sendSecurityEmailCodeBtn = document.getElementById('sendSecurityEmailCodeBtn');
  const securityEmailCodeWrap = document.getElementById('securityEmailCodeWrap');
  const securityEmailCodeInput = document.getElementById('securityEmailCodeInput');
  const verifySecurityEmailCodeBtn = document.getElementById('verifySecurityEmailCodeBtn');
  let currentSecurityEmailRequestId = null;

  // 8. Recovery Email Elements
  const recoveryEmailDisplayWrap = document.getElementById('recoveryEmailDisplayWrap');
  const currentRecoveryEmailText = document.getElementById('currentRecoveryEmailText');
  const changeRecoveryEmailBtn = document.getElementById('changeRecoveryEmailBtn');
  const recoveryEmailSetupWrap = document.getElementById('recoveryEmailSetupWrap');
  const recoveryEmailInput = document.getElementById('recoveryEmailInput');
  const sendRecoveryVerificationCodeBtn = document.getElementById('sendRecoveryVerificationCodeBtn');
  const recoveryCodeInputWrap = document.getElementById('recoveryCodeInputWrap');
  const recoveryVerificationCodeInput = document.getElementById('recoveryVerificationCodeInput');
  const confirmRecoveryCodeBtn = document.getElementById('confirmRecoveryCodeBtn');
  let currentRecoveryVerificationRequestId = null;

  // ---------------------------------------------------------------------------
  // Web Crypto API Helpers
  // ---------------------------------------------------------------------------

  function hexToBytes(hexString) {
    if (!hexString) return new Uint8Array(0);
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function bufferToHex(buffer) {
    const byteView = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < byteView.length; i++) {
      hex += byteView[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  function generateRandomSalt() {
    const salt = new Uint8Array(16);
    window.crypto.getRandomValues(salt);
    return salt;
  }

  async function computeHash(password, saltBytes) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      baseKey,
      HASH_BITS
    );

    return bufferToHex(derivedBits);
  }

  function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) {
      mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return mismatch === 0;
  }

  /**
   * Verifies an entered credential against stored master password or PIN.
   */
  async function verifyCredential(enteredValue) {
    if (!enteredValue) return false;

    const data = await chrome.storage.local.get([
      'authCredential',
      'authMode',
      'cpl_auth_mode',
      'passwordHash',
      'salt',
      'cpl_password_hash',
      'cpl_password_salt',
      'cpl_pin_hash',
      'cpl_pin_salt'
    ]);

    const mode = data.authMode || data.cpl_auth_mode || (data.authCredential ? data.authCredential.mode : 'password');

    let storedHash = null;
    let storedSalt = null;

    if (mode === 'pin') {
      storedHash = (data.authCredential && data.authCredential.mode === 'pin' ? data.authCredential.hash : null) || data.cpl_pin_hash;
      storedSalt = (data.authCredential && data.authCredential.mode === 'pin' ? data.authCredential.salt : null) || data.cpl_pin_salt;
    } else {
      storedHash = (data.authCredential && data.authCredential.mode === 'password' ? data.authCredential.hash : null) || data.passwordHash || data.cpl_password_hash;
      storedSalt = (data.authCredential && data.authCredential.mode === 'password' ? data.authCredential.salt : null) || data.salt || data.cpl_password_salt;
    }

    if (!storedHash || !storedSalt) {
      return false;
    }

    const saltBytes = hexToBytes(storedSalt);
    const candidateHash = await computeHash(enteredValue, saltBytes);
    return timingSafeEqual(candidateHash, storedHash);
  }

  // ---------------------------------------------------------------------------
  // Protected Settings Guard (Section 7)
  // ---------------------------------------------------------------------------

  function isProtectionEnabled() {
    return protectSecuritySettingsToggle.checked;
  }

  /**
   * Wraps sensitive operations. If protection is enabled, opens verification modal.
   * If verified, executes callback and logs SETTINGS_AUTHENTICATED.
   */
  async function requireSecurityProtection(actionCallback, revertElement = null) {
    if (!isProtectionEnabled()) {
      await actionCallback();
      return;
    }

    pendingProtectedAction = actionCallback;
    pendingRevertElement = revertElement;
    openVerifyModal();
  }

  function openVerifyModal() {
    verifyCredentialInput.value = '';
    verifyModalAlert.style.display = 'none';
    securityVerifyModal.style.display = 'flex';
    verifyCredentialInput.focus();
  }

  function closeVerifyModal() {
    securityVerifyModal.style.display = 'none';
    verifyCredentialInput.value = '';
    if (pendingRevertElement) {
      if (typeof pendingRevertElement === 'function') {
        pendingRevertElement();
      }
      pendingRevertElement = null;
    }
    pendingProtectedAction = null;
  }

  if (closeVerifyModalX) closeVerifyModalX.addEventListener('click', closeVerifyModal);
  if (closeVerifyModalBtn) closeVerifyModalBtn.addEventListener('click', closeVerifyModal);

  if (securityVerifyForm) {
    securityVerifyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      verifyModalAlert.style.display = 'none';

      const entered = verifyCredentialInput.value.trim();
      if (!entered) {
        showVerifyAlert('Please enter your credential.', 'alert-error');
        return;
      }

      confirmVerifyBtn.disabled = true;
      confirmVerifyBtn.textContent = 'Verifying...';

      try {
        const isValid = await verifyCredential(entered);
        if (!isValid) {
          showVerifyAlert('Incorrect password or PIN.', 'alert-error');
          verifyCredentialInput.value = '';
          verifyCredentialInput.focus();
          return;
        }

        // Successfully verified
        securityVerifyModal.style.display = 'none';
        pendingRevertElement = null; // Don't revert
        const action = pendingProtectedAction;
        pendingProtectedAction = null;

        chrome.runtime.sendMessage({
          type: 'LOG_SECURITY_EVENT',
          payload: {
            description: 'Security settings authenticated',
            type: 'SETTINGS_AUTHENTICATED'
          }
        }).catch(() => {});

        if (action) {
          await action();
        }

        await loadSecurityLogs();
        await updateSecurityStatusCard();

      } catch (err) {
        showVerifyAlert('Verification error. Please try again.', 'alert-error');
      } finally {
        confirmVerifyBtn.disabled = false;
        confirmVerifyBtn.textContent = 'Verify & Proceed';
      }
    });
  }

  function showVerifyAlert(msg, className) {
    verifyModalAlert.textContent = msg;
    verifyModalAlert.className = `alert-box ${className}`;
    verifyModalAlert.style.display = 'block';
  }

  // ---------------------------------------------------------------------------
  // Preferences & Security Status Loading
  // ---------------------------------------------------------------------------

  await loadPreferences();
  await loadSecurityLogs();

  async function loadPreferences() {
    chrome.storage.local.get([
      'settings',
      'cpl_settings',
      'profileName',
      'cpl_profile_name',
      'cpl_profile_avatar',
      'avatar',
      'cpl_auth_mode',
      'authMode',
      'cpl_pin_hash',
      'cpl_pin_salt',
      'authCredential',
      'cpl_theme',
      'cpl_metrics',
      'systemIdleLock',
      'systemIdleTimeout',
      'lockOnStartup',
      'protectSecuritySettings'
    ], (data) => {
      const settings = data.cpl_settings || data.settings || {};

      // 1. Theme
      const theme = data.cpl_theme || 'chrome';
      document.documentElement.setAttribute('data-theme', theme);
      updateThemeSelection(theme);

      // 2. Profile Identity
      const name = data.profileName || data.cpl_profile_name || 'Vamsi Greeshma';
      if (profileNameInput) {
        profileNameInput.value = name;
      }
      if (profileEmailInput) {
        const storedEmail = data.cpl_profile_email || data.profileEmail || data.cpl_security_email || data.verifiedSecurityEmail || data.securityEmail || data.cpl_recovery_email || data.recoveryEmail || '';
        profileEmailInput.value = storedEmail;

        if (chrome.identity && chrome.identity.getProfileUserInfo) {
          try {
            chrome.identity.getProfileUserInfo({ accountStatus: 'ANY' }, (info) => {
              if (!chrome.runtime.lastError && info && info.email) {
                profileEmailInput.value = info.email;
                chrome.storage.local.set({ cpl_profile_email: info.email }).catch(() => {});
              }
            });
          } catch {}
        }
      }
      selectedAvatar = data.avatar || data.cpl_profile_avatar || 'monogram';
      updateAvatarSelection(selectedAvatar, name);

      // 3. Security Settings Toggles
      protectSecuritySettingsToggle.checked = data.protectSecuritySettings !== undefined 
        ? Boolean(data.protectSecuritySettings) 
        : (settings.protectSecuritySettings !== false);

      lockOnStartupToggle.checked = data.lockOnStartup !== undefined 
        ? Boolean(data.lockOnStartup) 
        : (settings.lockOnStartup !== false);

      // 4. System Idle Lock & Inactivity
      systemIdleLockToggle.checked = data.systemIdleLock !== undefined 
        ? Boolean(data.systemIdleLock) 
        : (settings.systemIdleLock !== false);

      const idleTimeoutSecs = data.systemIdleTimeout || settings.systemIdleTimeout || 600;
      systemIdleTimeoutSelect.value = String(idleTimeoutSecs);
      updateIdleStatusText(systemIdleLockToggle.checked, idleTimeoutSecs);

      // Unified idle: lockOnInactive and autoLockMinutes are derived from idle settings

      // 5. Privacy & Shortcuts Toggles
      lockMuteAudioToggle.checked = settings.muteOnLock !== false && settings.autoMute !== false;
      lockCloakTitleToggle.checked = settings.cloakTabTitle !== false;
      lockWarningToggle.checked = settings.showInactivityWarning !== false;
      if (enableContextMenuLockToggle) {
        enableContextMenuLockToggle.checked = settings.enableContextMenuLock !== false;
      }

      // 6. Authentication Mode & PIN button visibility
      const resolvedAuthMode = data.authMode || data.cpl_auth_mode || (data.authCredential ? data.authCredential.mode : 'password');
      const hasPin = Boolean(data.cpl_pin_hash || (data.authCredential && data.authCredential.mode === 'pin'));

      if (resolvedAuthMode === 'pin') {
        authModePinRadio.checked = true;
      } else {
        authModePasswordRadio.checked = true;
      }

      // "Change PIN" button is visible when PIN mode is active or configured
      openChangePinModalBtn.style.display = hasPin ? 'inline-flex' : 'none';

      // 7. Telemetry Metrics
      const metrics = data.cpl_metrics || {};
      if (metricTotalLocks) metricTotalLocks.textContent = metrics.totalLocks || 0;
      if (metricTotalUnlocks) metricTotalUnlocks.textContent = metrics.totalUnlocks || 0;
      if (metricBlockedIntrusions) metricBlockedIntrusions.textContent = metrics.blockedIntrusions || 0;
      if (metricLastActive) {
        if (metrics.lastUnlockedTime) {
          const ago = Math.max(0, Math.floor((Date.now() - metrics.lastUnlockedTime) / 60000));
          metricLastActive.textContent = ago < 1 ? 'Just now' : `${ago}m ago`;
        } else {
          metricLastActive.textContent = 'Active';
        }
      }

      // 8. Update Security Status Card
      updateSecurityStatusCard(data);

      // 9. Backend API URL
      if (backendApiUrlInput) {
        backendApiUrlInput.value = data.cpl_backend_url || 'http://localhost:3000';
      }

      // 10. Security Email & Identity Loading
      loadSecurityEmailSettings(data);

      // 11. Recovery Email Loading
      loadRecoveryEmailSettings(data);
    });
  }

  async function updateSecurityStatusCard(providedData = null) {
    const data = providedData || await chrome.storage.local.get([
      'authMode',
      'cpl_auth_mode',
      'authCredential',
      'systemIdleLock',
      'systemIdleTimeout',
      'lockOnStartup',
      'settings',
      'cpl_settings',
      'cpl_security_logs'
    ]);

    const settings = data.cpl_settings || data.settings || {};
    const mode = data.authMode || data.cpl_auth_mode || (data.authCredential ? data.authCredential.mode : 'password');
    const isIdleEnabled = data.systemIdleLock !== undefined ? Boolean(data.systemIdleLock) : (settings.systemIdleLock !== false);
    const idleTimeoutSecs = data.systemIdleTimeout || settings.systemIdleTimeout || 600;
    const isStartupEnabled = data.lockOnStartup !== undefined ? Boolean(data.lockOnStartup) : (settings.lockOnStartup !== false);
    const isMuteEnabled = settings.muteOnLock !== false && settings.autoMute !== false;

    if (statusAuthMode) {
      statusAuthMode.textContent = mode === 'pin' ? '6-Digit PIN' : 'Password';
    }

    if (statusIdleLock) {
      const mins = Math.round(idleTimeoutSecs / 60);
      statusIdleLock.textContent = isIdleEnabled ? `${mins} min${mins > 1 ? 's' : ''}` : 'Disabled';
      statusIdleLock.className = isIdleEnabled ? 'status-item-value' : 'status-item-value status-badge-inactive';
    }

    if (statusStartupLock) {
      statusStartupLock.textContent = isStartupEnabled ? 'ON' : 'OFF';
      statusStartupLock.className = isStartupEnabled ? 'status-item-value status-badge-active' : 'status-item-value status-badge-inactive';
    }

    if (statusAutoMute) {
      statusAutoMute.textContent = isMuteEnabled ? 'ON' : 'OFF';
      statusAutoMute.className = isMuteEnabled ? 'status-item-value status-badge-active' : 'status-item-value status-badge-inactive';
    }

    if (statusLastEvent) {
      const logs = Array.isArray(data.cpl_security_logs) ? data.cpl_security_logs : [];
      if (logs.length > 0 && logs[0].timestamp) {
        statusLastEvent.textContent = formatLogTime(logs[0].timestamp);
      } else {
        statusLastEvent.textContent = 'Active';
      }
    }
  }

  function updateIdleStatusText(isEnabled, timeoutSecs) {
    if (!idleStatusText) return;
    if (isEnabled) {
      const mins = Math.round(timeoutSecs / 60);
      const text = mins === 60 ? '1 hour' : `${mins} minute${mins > 1 ? 's' : ''}`;
      idleStatusText.textContent = `Your profile will automatically lock after ${text} of system inactivity.`;
    } else {
      idleStatusText.textContent = 'System idle locking is disabled.';
    }
  }

  // ---------------------------------------------------------------------------
  // Security Alert Email & Secondary Recovery Email Handlers (Features 2, 3, 4)
  // ---------------------------------------------------------------------------

  function maskEmail(email) {
    if (!email || !email.includes('@')) return '***@***.***';
    const parts = email.split('@');
    const user = parts[0];
    const domain = parts[1];
    const maskedUser = user.length <= 2 
      ? user[0] + '***' 
      : user[0] + '***' + user[user.length - 1];
    return `${maskedUser}@${domain}`;
  }

  async function loadSecurityEmailSettings(data = null) {
    try {
      chrome.runtime.sendMessage({ type: 'GET_PROFILE_IDENTITY' }, async (resp) => {
        const userInfo = resp?.userInfo;
        if (userInfo && userInfo.email) {
          if (detectedProfileEmailWrap) detectedProfileEmailWrap.style.display = 'block';
          if (detectedProfileEmailText) detectedProfileEmailText.textContent = userInfo.email;
          if (manualSecurityEmailWrap) manualSecurityEmailWrap.style.display = 'none';
        } else {
          if (detectedProfileEmailWrap) detectedProfileEmailWrap.style.display = 'none';
          if (manualSecurityEmailWrap) manualSecurityEmailWrap.style.display = 'block';

          const localData = data || await chrome.storage.local.get(['cpl_security_email', 'verifiedSecurityEmail', 'securityEmail']);
          const email = localData.cpl_security_email || localData.verifiedSecurityEmail || localData.securityEmail;

          if (email) {
            if (securityEmailVerifiedStatus) securityEmailVerifiedStatus.style.display = 'block';
            if (verifiedSecurityEmailLabel) verifiedSecurityEmailLabel.textContent = email;
            if (securityEmailInputGroup) securityEmailInputGroup.style.display = 'none';
          } else {
            if (securityEmailVerifiedStatus) securityEmailVerifiedStatus.style.display = 'none';
            if (securityEmailInputGroup) securityEmailInputGroup.style.display = 'block';
          }
        }
      });
    } catch {
      if (manualSecurityEmailWrap) manualSecurityEmailWrap.style.display = 'block';
    }
  }

  async function loadRecoveryEmailSettings(data = null) {
    const localData = data || await chrome.storage.local.get([
      'cpl_recovery_email',
      'recoveryEmail',
      'cpl_recovery_verified',
      'recoveryEmailVerified'
    ]);

    const email = localData.cpl_recovery_email || localData.recoveryEmail;
    const isVerified = Boolean(localData.cpl_recovery_verified || localData.recoveryEmailVerified);

    if (email && isVerified) {
      if (recoveryEmailDisplayWrap) recoveryEmailDisplayWrap.style.display = 'block';
      if (currentRecoveryEmailText) currentRecoveryEmailText.textContent = maskEmail(email);
      if (recoveryEmailSetupWrap) recoveryEmailSetupWrap.style.display = 'none';
    } else {
      if (recoveryEmailDisplayWrap) recoveryEmailDisplayWrap.style.display = 'none';
      if (recoveryEmailSetupWrap) recoveryEmailSetupWrap.style.display = 'block';
      if (recoveryEmailInput && email) recoveryEmailInput.value = email;
    }
  }

  // Backend API URL Save & Test
  if (saveBackendUrlBtn && backendApiUrlInput) {
    saveBackendUrlBtn.addEventListener('click', async () => {
      const urlVal = (backendApiUrlInput.value || '').trim() || 'http://localhost:3000';
      await chrome.storage.local.set({ cpl_backend_url: urlVal });
      showToast('Backend API URL saved.');
    });
  }

  if (testBackendBtn && backendApiUrlInput) {
    testBackendBtn.addEventListener('click', async () => {
      const urlVal = (backendApiUrlInput.value || '').trim() || 'http://localhost:3000';
      testBackendBtn.disabled = true;
      testBackendBtn.textContent = 'Testing...';
      try {
        const res = await fetch(`${urlVal}/api/health`);
        const json = await res.json();
        if (res.ok && json.status === 'ok') {
          showToast('✓ Backend connected successfully!');
        } else {
          showToast('⚠️ Backend responded with an error.');
        }
      } catch {
        showToast('⚠️ Could not connect to backend server.');
      } finally {
        testBackendBtn.disabled = false;
        testBackendBtn.textContent = 'Test API';
      }
    });
  }

  // Security Email Code Verification
  if (sendSecurityEmailCodeBtn && securityEmailInput) {
    sendSecurityEmailCodeBtn.addEventListener('click', async () => {
      const email = (securityEmailInput.value || '').trim();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showToast('Please enter a valid security email address.');
        return;
      }
      sendSecurityEmailCodeBtn.disabled = true;
      sendSecurityEmailCodeBtn.textContent = 'Sending...';
      try {
        const backendUrl = (backendApiUrlInput ? backendApiUrlInput.value.trim() : '') || 'http://localhost:3000';
        const res = await fetch(`${backendUrl}/api/send-email-verification`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, type: 'security' })
        });
        const json = await res.json();
        if (res.ok && json.success) {
          currentSecurityEmailRequestId = json.requestId;
          if (securityEmailCodeWrap) securityEmailCodeWrap.style.display = 'block';
          if (securityEmailCodeInput) securityEmailCodeInput.focus();
          showToast('Verification code sent to ' + maskEmail(email));
        } else {
          showToast(json.error || 'Failed to send verification code.');
        }
      } catch {
        showToast('Backend server unavailable.');
      } finally {
        sendSecurityEmailCodeBtn.disabled = false;
        sendSecurityEmailCodeBtn.textContent = 'Verify Email';
      }
    });
  }

  if (verifySecurityEmailCodeBtn && securityEmailCodeInput) {
    verifySecurityEmailCodeBtn.addEventListener('click', async () => {
      const code = (securityEmailCodeInput.value || '').trim();
      const email = (securityEmailInput.value || '').trim();
      if (!code || code.length !== 6) {
        showToast('Please enter the 6-digit code.');
        return;
      }
      verifySecurityEmailCodeBtn.disabled = true;
      verifySecurityEmailCodeBtn.textContent = 'Verifying...';
      try {
        const backendUrl = (backendApiUrlInput ? backendApiUrlInput.value.trim() : '') || 'http://localhost:3000';
        const res = await fetch(`${backendUrl}/api/confirm-email-verification`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requestId: currentSecurityEmailRequestId, code })
        });
        const json = await res.json();
        if (res.ok && json.success) {
          await chrome.storage.local.set({
            cpl_security_email: email,
            verifiedSecurityEmail: email,
            securityEmail: email
          });
          if (securityEmailVerifiedStatus) securityEmailVerifiedStatus.style.display = 'block';
          if (verifiedSecurityEmailLabel) verifiedSecurityEmailLabel.textContent = email;
          if (securityEmailInputGroup) securityEmailInputGroup.style.display = 'none';
          if (securityEmailCodeWrap) securityEmailCodeWrap.style.display = 'none';
          showToast('Security alert email verified!');
        } else {
          showToast(json.error || 'Incorrect verification code.');
        }
      } catch {
        showToast('Backend server unavailable.');
      } finally {
        verifySecurityEmailCodeBtn.disabled = false;
        verifySecurityEmailCodeBtn.textContent = 'Confirm Code';
      }
    });
  }

  if (changeSecurityEmailBtn) {
    changeSecurityEmailBtn.addEventListener('click', () => {
      requireSecurityProtection(() => {
        if (securityEmailVerifiedStatus) securityEmailVerifiedStatus.style.display = 'none';
        if (securityEmailInputGroup) securityEmailInputGroup.style.display = 'block';
        if (securityEmailCodeWrap) securityEmailCodeWrap.style.display = 'none';
        if (securityEmailInput) securityEmailInput.focus();
      });
    });
  }

  // Recovery Email Handlers
  if (changeRecoveryEmailBtn) {
    changeRecoveryEmailBtn.addEventListener('click', () => {
      requireSecurityProtection(() => {
        chrome.runtime.sendMessage({
          type: 'LOG_SECURITY_EVENT',
          payload: {
            description: 'Recovery email modification initiated',
            type: 'RECOVERY_EMAIL_CHANGED'
          }
        }).catch(() => {});
        if (recoveryEmailDisplayWrap) recoveryEmailDisplayWrap.style.display = 'none';
        if (recoveryEmailSetupWrap) recoveryEmailSetupWrap.style.display = 'block';
        if (recoveryCodeInputWrap) recoveryCodeInputWrap.style.display = 'none';
        if (recoveryEmailInput) recoveryEmailInput.focus();
      });
    });
  }

  if (sendRecoveryVerificationCodeBtn && recoveryEmailInput) {
    sendRecoveryVerificationCodeBtn.addEventListener('click', async () => {
      const email = (recoveryEmailInput.value || '').trim();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showToast('Please enter a valid recovery email address.');
        return;
      }
      sendRecoveryVerificationCodeBtn.disabled = true;
      sendRecoveryVerificationCodeBtn.textContent = 'Sending...';
      try {
        const backendUrl = (backendApiUrlInput ? backendApiUrlInput.value.trim() : '') || 'http://localhost:3000';
        const res = await fetch(`${backendUrl}/api/send-email-verification`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, type: 'recovery' })
        });
        const json = await res.json();
        if (res.ok && json.success) {
          currentRecoveryVerificationRequestId = json.requestId;
          if (recoveryCodeInputWrap) recoveryCodeInputWrap.style.display = 'block';
          if (recoveryVerificationCodeInput) recoveryVerificationCodeInput.focus();
          showToast('Verification code sent to ' + maskEmail(email));
        } else {
          showToast(json.error || 'Failed to send verification code.');
        }
      } catch {
        showToast('Backend server unavailable.');
      } finally {
        sendRecoveryVerificationCodeBtn.disabled = false;
        sendRecoveryVerificationCodeBtn.textContent = 'Send Verification Code';
      }
    });
  }

  if (confirmRecoveryCodeBtn && recoveryVerificationCodeInput) {
    confirmRecoveryCodeBtn.addEventListener('click', async () => {
      const code = (recoveryVerificationCodeInput.value || '').trim();
      const email = (recoveryEmailInput.value || '').trim();
      if (!code || code.length !== 6) {
        showToast('Please enter the 6-digit code.');
        return;
      }
      confirmRecoveryCodeBtn.disabled = true;
      confirmRecoveryCodeBtn.textContent = 'Verifying...';
      try {
        const backendUrl = (backendApiUrlInput ? backendApiUrlInput.value.trim() : '') || 'http://localhost:3000';
        const res = await fetch(`${backendUrl}/api/confirm-email-verification`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requestId: currentRecoveryVerificationRequestId, code })
        });
        const json = await res.json();
        if (res.ok && json.success) {
          await chrome.storage.local.set({
            cpl_recovery_email: email,
            recoveryEmail: email,
            cpl_recovery_verified: true,
            recoveryEmailVerified: true
          });
          chrome.runtime.sendMessage({
            type: 'LOG_SECURITY_EVENT',
            payload: {
              description: 'Recovery email verified',
              type: 'RECOVERY_EMAIL_VERIFIED'
            }
          }).catch(() => {});
          if (recoveryEmailDisplayWrap) recoveryEmailDisplayWrap.style.display = 'block';
          if (currentRecoveryEmailText) currentRecoveryEmailText.textContent = maskEmail(email);
          if (recoveryEmailSetupWrap) recoveryEmailSetupWrap.style.display = 'none';
          if (recoveryCodeInputWrap) recoveryCodeInputWrap.style.display = 'none';
          showToast('✓ Recovery email verified successfully!');
          await loadSecurityLogs();
        } else {
          showToast(json.error || 'Incorrect verification code.');
        }
      } catch {
        showToast('Backend server unavailable.');
      } finally {
        confirmRecoveryCodeBtn.disabled = false;
        confirmRecoveryCodeBtn.textContent = 'Verify';
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Lock Now Button (Section 9)
  // ---------------------------------------------------------------------------
  lockNowBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'LOCK_PROFILE' }, () => {
      window.location.href = 'lock.html';
    });
  });

  // ---------------------------------------------------------------------------
  // Profile Identity & Avatar
  // ---------------------------------------------------------------------------

  function updateAvatarSelection(avatarVal, profileName) {
    if (!avatarPickerGrid) return;
    const name = profileName || (profileNameInput ? profileNameInput.value : '') || 'VG';
    const monogramBtn = avatarPickerGrid.querySelector('[data-avatar="monogram"]');
    if (monogramBtn) {
      const initials = name.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase() || 'VG';
      monogramBtn.textContent = initials;
    }

    const buttons = avatarPickerGrid.querySelectorAll('.avatar-option');
    buttons.forEach((btn) => {
      if (btn.getAttribute('data-avatar') === avatarVal) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });
  }

  if (avatarPickerGrid) {
    avatarPickerGrid.addEventListener('click', async (e) => {
      const btn = e.target.closest('.avatar-option');
      if (!btn) return;
      const avatarVal = btn.getAttribute('data-avatar');
      if (!avatarVal) return;
      selectedAvatar = avatarVal;
      updateAvatarSelection(selectedAvatar, profileNameInput ? profileNameInput.value : '');
      await chrome.storage.local.set({ 
        cpl_profile_avatar: selectedAvatar,
        avatar: selectedAvatar
      });
      showToast(`Avatar updated: ${avatarVal === 'monogram' ? 'Monogram' : avatarVal}`);
    });
  }

  if (profileNameForm) {
    profileNameForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const newName = (profileNameInput.value || '').trim();
      if (!newName) {
        showToast('Profile name cannot be empty.');
        return;
      }
      const newEmail = profileEmailInput ? (profileEmailInput.value || '').trim() : '';
      const payload = {
        cpl_profile_name: newName,
        profileName: newName,
        cpl_profile_avatar: selectedAvatar,
        avatar: selectedAvatar
      };
      if (newEmail) {
        payload.cpl_profile_email = newEmail;
        payload.cpl_recovery_email = newEmail;
        payload.cpl_recovery_verified = true;
      }
      await chrome.storage.local.set(payload);

      updateAvatarSelection(selectedAvatar, newName);
      showToast(`Profile identity saved: ${newName}`);
    });
  }

  // ---------------------------------------------------------------------------
  // MODAL 1: CHANGE PASSWORD (Section 4)
  // ---------------------------------------------------------------------------

  openChangePasswordModalBtn.addEventListener('click', () => {
    requireSecurityProtection(() => {
      modalCurrentPassword.value = '';
      modalNewPassword.value = '';
      modalConfirmPassword.value = '';
      modalPasswordAlert.style.display = 'none';
      changePasswordModal.style.display = 'flex';
      modalCurrentPassword.focus();
    });
  });

  function closePasswordModal() {
    changePasswordModal.style.display = 'none';
    modalCurrentPassword.value = '';
    modalNewPassword.value = '';
    modalConfirmPassword.value = '';
  }

  if (closePasswordModalX) closePasswordModalX.addEventListener('click', closePasswordModal);
  if (closePasswordModalBtn) closePasswordModalBtn.addEventListener('click', closePasswordModal);

  changePasswordModalForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    modalPasswordAlert.style.display = 'none';

    const curr = modalCurrentPassword.value;
    const next = modalNewPassword.value;
    const confirm = modalConfirmPassword.value;

    if (!curr) {
      showPasswordAlert('Please enter your current password.', 'alert-error');
      modalCurrentPassword.focus();
      return;
    }

    if (!next) {
      showPasswordAlert('Please enter a new password.', 'alert-error');
      modalNewPassword.focus();
      return;
    }

    if (next.length < 6) {
      showPasswordAlert('New password must be at least 6 characters long.', 'alert-error');
      modalNewPassword.focus();
      return;
    }

    if (next !== confirm) {
      showPasswordAlert('New passwords do not match. Please verify.', 'alert-error');
      modalConfirmPassword.focus();
      return;
    }

    submitChangePasswordBtn.disabled = true;
    submitChangePasswordBtn.textContent = 'Updating...';

    try {
      // 1. Verify current password
      const data = await chrome.storage.local.get([
        'passwordHash',
        'salt',
        'cpl_password_hash',
        'cpl_password_salt',
        'authCredential'
      ]);

      const storedHash = (data.authCredential && data.authCredential.mode === 'password' ? data.authCredential.hash : null) || data.passwordHash || data.cpl_password_hash;
      const storedSalt = (data.authCredential && data.authCredential.mode === 'password' ? data.authCredential.salt : null) || data.salt || data.cpl_password_salt;

      if (!storedHash || !storedSalt) {
        showPasswordAlert('Configuration error. Please complete setup.', 'alert-error');
        return;
      }

      const currentSaltBytes = hexToBytes(storedSalt);
      const currCandidateHash = await computeHash(curr, currentSaltBytes);

      if (!timingSafeEqual(currCandidateHash, storedHash)) {
        showPasswordAlert('Incorrect current password.', 'alert-error');
        modalCurrentPassword.value = '';
        modalCurrentPassword.focus();
        return;
      }

      // 2. Derive new password with fresh random 16-byte salt
      const newSaltBytes = generateRandomSalt();
      const newSaltHex = bufferToHex(newSaltBytes);
      const newHashHex = await computeHash(next, newSaltBytes);

      // 3. Clear DOM
      modalCurrentPassword.value = '';
      modalNewPassword.value = '';
      modalConfirmPassword.value = '';

      // 4. Save in structured & backward-compatible format
      const authCredential = {
        mode: 'password',
        hash: newHashHex,
        salt: newSaltHex,
        iterations: PBKDF2_ITERATIONS
      };

      await chrome.storage.local.set({
        passwordHash: newHashHex,
        salt: newSaltHex,
        cpl_password_hash: newHashHex,
        cpl_password_salt: newSaltHex,
        authCredential: authCredential,
        authMode: 'password',
        cpl_auth_mode: 'password'
      });

      closePasswordModal();
      showToast('Password changed successfully.');

      chrome.runtime.sendMessage({
        type: 'LOG_SECURITY_EVENT',
        payload: {
          description: 'Master password successfully changed',
          type: 'PASSWORD_CHANGED'
        }
      }).catch(() => {});

      await loadSecurityLogs();
      await updateSecurityStatusCard();

    } catch {
      showPasswordAlert('Failed to update password. Please try again.', 'alert-error');
    } finally {
      submitChangePasswordBtn.disabled = false;
      submitChangePasswordBtn.textContent = 'Save Password';
    }
  });

  function showPasswordAlert(msg, className) {
    modalPasswordAlert.textContent = msg;
    modalPasswordAlert.className = `alert-box ${className}`;
    modalPasswordAlert.style.display = 'block';
  }

  // ---------------------------------------------------------------------------
  // MODAL 2: CHANGE PIN (Section 5)
  // ---------------------------------------------------------------------------

  openChangePinModalBtn.addEventListener('click', () => {
    requireSecurityProtection(() => {
      modalCurrentPin.value = '';
      modalNewPin.value = '';
      modalConfirmPin.value = '';
      modalPinAlert.style.display = 'none';
      changePinModal.style.display = 'flex';
      modalCurrentPin.focus();
    });
  });

  function closePinModal() {
    changePinModal.style.display = 'none';
    modalCurrentPin.value = '';
    modalNewPin.value = '';
    modalConfirmPin.value = '';
  }

  if (closePinModalX) closePinModalX.addEventListener('click', closePinModal);
  if (closePinModalBtn) closePinModalBtn.addEventListener('click', closePinModal);

  changePinModalForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    modalPinAlert.style.display = 'none';

    const curr = modalCurrentPin.value.trim();
    const next = modalNewPin.value.trim();
    const confirm = modalConfirmPin.value.trim();

    if (!/^\d{6}$/.test(curr)) {
      showPinAlert('Current PIN must be exactly 6 numeric digits.', 'alert-error');
      modalCurrentPin.focus();
      return;
    }

    if (!/^\d{6}$/.test(next)) {
      showPinAlert('New PIN must be exactly 6 numeric digits.', 'alert-error');
      modalNewPin.focus();
      return;
    }

    if (next !== confirm) {
      showPinAlert('New PINs do not match. Please verify.', 'alert-error');
      modalConfirmPin.focus();
      return;
    }

    submitChangePinBtn.disabled = true;
    submitChangePinBtn.textContent = 'Updating...';

    try {
      // 1. Verify current PIN
      const data = await chrome.storage.local.get([
        'cpl_pin_hash',
        'cpl_pin_salt',
        'authCredential'
      ]);

      const storedHash = (data.authCredential && data.authCredential.mode === 'pin' ? data.authCredential.hash : null) || data.cpl_pin_hash;
      const storedSalt = (data.authCredential && data.authCredential.mode === 'pin' ? data.authCredential.salt : null) || data.cpl_pin_salt;

      if (!storedHash || !storedSalt) {
        showPinAlert('No PIN configured. Please set one first.', 'alert-error');
        return;
      }

      const saltBytes = hexToBytes(storedSalt);
      const currCandidateHash = await computeHash(curr, saltBytes);

      if (!timingSafeEqual(currCandidateHash, storedHash)) {
        showPinAlert('Incorrect current PIN.', 'alert-error');
        modalCurrentPin.value = '';
        modalCurrentPin.focus();
        return;
      }

      // 2. Hash new PIN with fresh salt
      const newSaltBytes = generateRandomSalt();
      const newSaltHex = bufferToHex(newSaltBytes);
      const newHashHex = await computeHash(next, newSaltBytes);

      modalCurrentPin.value = '';
      modalNewPin.value = '';
      modalConfirmPin.value = '';

      const authCredential = {
        mode: 'pin',
        hash: newHashHex,
        salt: newSaltHex,
        iterations: PBKDF2_ITERATIONS
      };

      await chrome.storage.local.set({
        cpl_pin_hash: newHashHex,
        cpl_pin_salt: newSaltHex,
        authCredential: authCredential,
        authMode: 'pin',
        cpl_auth_mode: 'pin',
        cpl_consecutive_failures: 0
      });

      closePinModal();
      showToast('PIN changed successfully.');

      chrome.runtime.sendMessage({
        type: 'LOG_SECURITY_EVENT',
        payload: {
          description: '6-Digit PIN successfully changed',
          type: 'PIN_CHANGED'
        }
      }).catch(() => {});

      await loadSecurityLogs();
      await updateSecurityStatusCard();

    } catch {
      showPinAlert('Failed to update PIN. Please try again.', 'alert-error');
    } finally {
      submitChangePinBtn.disabled = false;
      submitChangePinBtn.textContent = 'Save PIN';
    }
  });

  function showPinAlert(msg, className) {
    modalPinAlert.textContent = msg;
    modalPinAlert.className = `alert-box ${className}`;
    modalPinAlert.style.display = 'block';
  }

  // ---------------------------------------------------------------------------
  // MODAL 3: AUTHENTICATION MODE SWITCHING (Section 6)
  // ---------------------------------------------------------------------------

  async function handleAuthModeRadioClick(e) {
    const desiredMode = e.target.value;
    const data = await chrome.storage.local.get(['authMode', 'cpl_auth_mode', 'cpl_pin_hash']);
    const currentMode = data.authMode || data.cpl_auth_mode || 'password';

    if (desiredMode === currentMode) {
      return; // No change
    }

    // Always require current credential authentication to switch mode
    targetSwitchMode = desiredMode;
    openSwitchModeModal(currentMode, desiredMode);
  }

  authModePasswordRadio.addEventListener('click', handleAuthModeRadioClick);
  authModePinRadio.addEventListener('click', handleAuthModeRadioClick);

  function openSwitchModeModal(currentMode, newMode) {
    switchModeCurrentCred.value = '';
    switchToPinNew.value = '';
    switchToPinConfirm.value = '';
    switchToPasswordNew.value = '';
    switchToPasswordConfirm.value = '';
    switchModeAlert.style.display = 'none';

    switchModeCurrentLabel.textContent = currentMode === 'pin' ? 'Current 6-Digit PIN' : 'Current Master Password';
    switchModeCurrentCred.setAttribute('placeholder', currentMode === 'pin' ? 'Enter current 6-digit PIN' : 'Enter current master password');

    if (newMode === 'pin') {
      switchToPinWrap.style.display = 'block';
      switchToPasswordWrap.style.display = 'none';
      confirmSwitchModeBtn.textContent = 'Switch to PIN';
    } else {
      switchToPinWrap.style.display = 'none';
      switchToPasswordWrap.style.display = 'block';
      confirmSwitchModeBtn.textContent = 'Switch to Password';
    }

    switchAuthModeModal.style.display = 'flex';
    switchModeCurrentCred.focus();
  }

  function closeSwitchModeModal() {
    switchAuthModeModal.style.display = 'none';
    switchModeCurrentCred.value = '';
    // Revert radio button selection based on stored state
    chrome.storage.local.get(['authMode', 'cpl_auth_mode'], (d) => {
      const mode = d.authMode || d.cpl_auth_mode || 'password';
      if (mode === 'pin') {
        authModePinRadio.checked = true;
      } else {
        authModePasswordRadio.checked = true;
      }
    });
  }

  if (closeSwitchModeModalX) closeSwitchModeModalX.addEventListener('click', closeSwitchModeModal);
  if (closeSwitchModeModalBtn) closeSwitchModeModalBtn.addEventListener('click', closeSwitchModeModal);

  switchAuthModeForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    switchModeAlert.style.display = 'none';

    const curr = switchModeCurrentCred.value.trim();
    if (!curr) {
      showSwitchAlert('Please enter your current credential.', 'alert-error');
      switchModeCurrentCred.focus();
      return;
    }

    confirmSwitchModeBtn.disabled = true;
    confirmSwitchModeBtn.textContent = 'Verifying...';

    try {
      // 1. Verify current credential
      const isValid = await verifyCredential(curr);
      if (!isValid) {
        showSwitchAlert('Incorrect current credential.', 'alert-error');
        switchModeCurrentCred.value = '';
        switchModeCurrentCred.focus();
        return;
      }

      // 2. Validate and save new mode credential
      if (targetSwitchMode === 'pin') {
        const pin = switchToPinNew.value.trim();
        const confirmPin = switchToPinConfirm.value.trim();

        if (!/^\d{6}$/.test(pin)) {
          showSwitchAlert('New PIN must be exactly 6 numeric digits.', 'alert-error');
          switchToPinNew.focus();
          return;
        }

        if (pin !== confirmPin) {
          showSwitchAlert('New PINs do not match.', 'alert-error');
          switchToPinConfirm.focus();
          return;
        }

        const pinSaltBytes = generateRandomSalt();
        const pinSaltHex = bufferToHex(pinSaltBytes);
        const pinHashHex = await computeHash(pin, pinSaltBytes);

        const authCredential = {
          mode: 'pin',
          hash: pinHashHex,
          salt: pinSaltHex,
          iterations: PBKDF2_ITERATIONS
        };

        await chrome.storage.local.set({
          cpl_pin_hash: pinHashHex,
          cpl_pin_salt: pinSaltHex,
          authCredential: authCredential,
          authMode: 'pin',
          cpl_auth_mode: 'pin',
          cpl_consecutive_failures: 0
        });

        authModePinRadio.checked = true;
        openChangePinModalBtn.style.display = 'inline-flex';
        showToast('Authentication mode switched to 6-Digit PIN.');

      } else {
        const pwd = switchToPasswordNew.value;
        const confirmPwd = switchToPasswordConfirm.value;

        if (!pwd || pwd.length < 6) {
          showSwitchAlert('Master password must be at least 6 characters.', 'alert-error');
          switchToPasswordNew.focus();
          return;
        }

        if (pwd !== confirmPwd) {
          showSwitchAlert('Passwords do not match.', 'alert-error');
          switchToPasswordConfirm.focus();
          return;
        }

        const pwdSaltBytes = generateRandomSalt();
        const pwdSaltHex = bufferToHex(pwdSaltBytes);
        const pwdHashHex = await computeHash(pwd, pwdSaltBytes);

        const authCredential = {
          mode: 'password',
          hash: pwdHashHex,
          salt: pwdSaltHex,
          iterations: PBKDF2_ITERATIONS
        };

        await chrome.storage.local.set({
          passwordHash: pwdHashHex,
          salt: pwdSaltHex,
          cpl_password_hash: pwdHashHex,
          cpl_password_salt: pwdSaltHex,
          authCredential: authCredential,
          authMode: 'password',
          cpl_auth_mode: 'password'
        });

        authModePasswordRadio.checked = true;
        showToast('Authentication mode switched to Password.');
      }

      switchAuthModeModal.style.display = 'none';

      chrome.runtime.sendMessage({
        type: 'LOG_SECURITY_EVENT',
        payload: {
          description: `Authentication mode changed to ${targetSwitchMode === 'pin' ? '6-Digit PIN' : 'Password'}`,
          type: 'AUTH_MODE_CHANGED'
        }
      }).catch(() => {});

      await loadSecurityLogs();
      await updateSecurityStatusCard();

    } catch {
      showSwitchAlert('Failed to switch authentication mode.', 'alert-error');
    } finally {
      confirmSwitchModeBtn.disabled = false;
      confirmSwitchModeBtn.textContent = targetSwitchMode === 'pin' ? 'Switch to PIN' : 'Switch to Password';
    }
  });

  function showSwitchAlert(msg, className) {
    switchModeAlert.textContent = msg;
    switchModeAlert.className = `alert-box ${className}`;
    switchModeAlert.style.display = 'block';
  }

  // ---------------------------------------------------------------------------
  // Settings & Toggles Persistence (Sections 1, 7, 8, 14)
  // ---------------------------------------------------------------------------

  // 1. Require authentication to change security settings
  protectSecuritySettingsToggle.addEventListener('change', async (e) => {
    const isChecked = e.target.checked;
    if (!isChecked) {
      // Disabling protection is a sensitive action!
      requireSecurityProtection(async () => {
        await persistAllSettings();
        showToast('Setting protection disabled.');
      }, () => {
        protectSecuritySettingsToggle.checked = true; // revert if cancelled
      });
    } else {
      await persistAllSettings();
      showToast('Setting protection enabled.');
    }
  });

  // 2. Lock on Startup
  lockOnStartupToggle.addEventListener('change', async (e) => {
    const originalState = !e.target.checked;
    requireSecurityProtection(async () => {
      await persistAllSettings();
      showToast(`Startup lock: ${e.target.checked ? 'ON' : 'OFF'}`);
    }, () => {
      lockOnStartupToggle.checked = originalState;
    });
  });

  // 3. System Idle Lock Toggle (chrome.idle)
  systemIdleLockToggle.addEventListener('change', async (e) => {
    const originalState = !e.target.checked;
    requireSecurityProtection(async () => {
      const timeoutSecs = parseInt(systemIdleTimeoutSelect.value, 10);
      updateIdleStatusText(e.target.checked, timeoutSecs);
      await persistAllSettings();
      showToast(`System idle lock: ${e.target.checked ? 'Enabled' : 'Disabled'}`);
    }, () => {
      systemIdleLockToggle.checked = originalState;
      const timeoutSecs = parseInt(systemIdleTimeoutSelect.value, 10);
      updateIdleStatusText(originalState, timeoutSecs);
    });
  });

  // 4. System Idle Timeout Select
  systemIdleTimeoutSelect.addEventListener('change', async (e) => {
    const originalVal = systemIdleTimeoutSelect.getAttribute('data-prev') || '600';
    requireSecurityProtection(async () => {
      const timeoutSecs = parseInt(systemIdleTimeoutSelect.value, 10);
      systemIdleTimeoutSelect.setAttribute('data-prev', String(timeoutSecs));
      updateIdleStatusText(systemIdleLockToggle.checked, timeoutSecs);
      await persistAllSettings();
      const selectedText = systemIdleTimeoutSelect.options[systemIdleTimeoutSelect.selectedIndex].text;
      showToast(`Idle lock timeout set to ${selectedText}.`);
    }, () => {
      systemIdleTimeoutSelect.value = originalVal;
      updateIdleStatusText(systemIdleLockToggle.checked, parseInt(originalVal, 10));
    });
  });


  lockMuteAudioToggle.addEventListener('change', persistAllSettings);
  lockCloakTitleToggle.addEventListener('change', persistAllSettings);
  lockWarningToggle.addEventListener('change', persistAllSettings);
  if (enableContextMenuLockToggle) {
    enableContextMenuLockToggle.addEventListener('change', async () => {
      await persistAllSettings();
      showToast(enableContextMenuLockToggle.checked ? 'Right-click quick lock enabled' : 'Right-click quick lock disabled');
    });
  }

  async function persistAllSettings() {
    const systemIdleLock = systemIdleLockToggle.checked;
    const systemIdleTimeout = parseInt(systemIdleTimeoutSelect.value, 10);
    const lockOnStartup = lockOnStartupToggle.checked;
    const protectSecuritySettings = protectSecuritySettingsToggle.checked;

    // Derive autoLockMinutes from the unified idle timeout (convert seconds to minutes)
    const autoLockMinutes = systemIdleLock ? Math.round(systemIdleTimeout / 60) : 0;
    const lockOnInactive = systemIdleLock;
    const muteOnLock = lockMuteAudioToggle.checked;
    const cloakTabTitle = lockCloakTitleToggle.checked;
    const showInactivityWarning = lockWarningToggle.checked;
    const enableContextMenuLock = enableContextMenuLockToggle ? enableContextMenuLockToggle.checked : true;

    const structuredSettings = {
      systemIdleLock,
      systemIdleTimeout,
      lockOnStartup,
      protectSecuritySettings,
      autoLockMinutes,
      lockOnInactive,
      muteOnLock,
      autoMute: muteOnLock,
      cloakTabTitle,
      showInactivityWarning,
      enableContextMenuLock
    };

    await chrome.storage.local.set({
      settings: structuredSettings,
      cpl_settings: structuredSettings,
      systemIdleLock,
      systemIdleTimeout,
      lockOnStartup,
      protectSecuritySettings
    });

    chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      payload: structuredSettings
    }).catch(() => {});

    await updateSecurityStatusCard();
  }

  // ---------------------------------------------------------------------------
  // Theme Switching
  // ---------------------------------------------------------------------------

  function updateThemeSelection(activeTheme) {
    if (!themePickerGrid) return;
    const cards = themePickerGrid.querySelectorAll('.theme-card');
    cards.forEach((c) => {
      if (c.getAttribute('data-theme') === activeTheme) {
        c.classList.add('active');
      } else {
        c.classList.remove('active');
      }
    });
  }

  if (themePickerGrid) {
    themePickerGrid.addEventListener('click', async (e) => {
      const card = e.target.closest('.theme-card');
      if (!card) return;
      const theme = card.getAttribute('data-theme');
      if (!theme) return;
      document.documentElement.setAttribute('data-theme', theme);
      updateThemeSelection(theme);
      await chrome.storage.local.set({ cpl_theme: theme });
      const name = card.querySelector('.theme-name')?.textContent || theme;
      showToast(`Theme applied: ${name}`);
    });
  }

  // ---------------------------------------------------------------------------
  // Security Activity Audit Log (Section 11)
  // ---------------------------------------------------------------------------

  async function loadSecurityLogs() {
    if (!activityList) return;

    chrome.storage.local.get(['cpl_security_logs'], (data) => {
      const logs = Array.isArray(data.cpl_security_logs) ? data.cpl_security_logs : [];
      while (activityList.firstChild) {
        activityList.removeChild(activityList.firstChild);
      }

      if (logs.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'activity-empty';
        empty.textContent = 'No recent security events recorded.';
        activityList.appendChild(empty);
        return;
      }

      // Display latest 5 events
      const latestLogs = logs.slice(0, 5);

      latestLogs.forEach((log) => {
        const item = document.createElement('div');
        item.className = 'activity-item-v2';

        const left = document.createElement('div');
        left.className = 'activity-item-left';

        const iconEl = document.createElement('span');
        iconEl.className = 'activity-event-icon';
        iconEl.textContent = getEventIcon(log.type);

        const details = document.createElement('div');
        details.className = 'activity-event-details';

        const name = document.createElement('span');
        name.className = 'activity-event-name';
        name.textContent = getEventTitle(log.type, log.description);

        const time = document.createElement('span');
        time.className = 'activity-event-time';
        time.textContent = formatEventTime(log.timestamp);

        details.appendChild(name);
        details.appendChild(time);
        left.appendChild(iconEl);
        left.appendChild(details);
        item.appendChild(left);

        activityList.appendChild(item);
      });
    });
  }

  function getEventIcon(type) {
    const t = (type || '').toUpperCase();
    if (t === 'IDLE_LOCK') return '💤';
    if (t === 'STARTUP_LOCK') return '🚀';
    if (t === 'MANUAL_LOCK') return '🔒';
    if (t === 'PROFILE_LOCKED' || t === 'LOCK') return '🔒';
    if (t === 'PROFILE_UNLOCKED' || t === 'UNLOCK_SUCCESS') return '🔓';
    if (t === 'PASSWORD_CHANGED') return '🔑';
    if (t === 'PIN_CHANGED') return '🔢';
    if (t === 'PASSWORD_RESET') return '🔑';
    if (t === 'PIN_RESET') return '🔢';
    if (t === 'AUTH_MODE_CHANGED') return '⚙️';
    if (t === 'SETTINGS_AUTHENTICATED') return '🛡️';
    if (t === 'SECURITY_ALERT_SENT') return '⚠️';
    if (t === 'RECOVERY_REQUESTED') return '📬';
    if (t === 'OTP_SENT') return '✉️';
    if (t === 'OTP_VERIFIED') return '✓';
    if (t === 'OTP_FAILED') return '❌';
    if (t === 'OTP_EXPIRED') return '⏳';
    if (t === 'RECOVERY_EMAIL_CHANGED') return '📧';
    if (t === 'RECOVERY_EMAIL_VERIFIED') return '✓';
    if (t === 'FAILED_ATTEMPT' || t === 'UNLOCK_FAILED') return '⚠️';
    if (t === 'RESET') return '⚠️';
    return 'ℹ️';
  }

  function getEventTitle(type, defaultDesc) {
    const t = (type || '').toUpperCase();
    if (t === 'IDLE_LOCK') return 'System Idle Lock';
    if (t === 'STARTUP_LOCK') return 'Startup Lock Engaged';
    if (t === 'MANUAL_LOCK') return 'Manual Lock';
    if (t === 'PROFILE_LOCKED' || t === 'LOCK') return 'Profile Locked';
    if (t === 'PROFILE_UNLOCKED' || t === 'UNLOCK_SUCCESS') return 'Profile Unlocked';
    if (t === 'PASSWORD_CHANGED') return 'Password Changed';
    if (t === 'PIN_CHANGED') return 'PIN Changed';
    if (t === 'PASSWORD_RESET') return 'Password Reset via OTP';
    if (t === 'PIN_RESET') return 'PIN Reset via OTP';
    if (t === 'AUTH_MODE_CHANGED') return 'Auth Mode Changed';
    if (t === 'SETTINGS_AUTHENTICATED') return 'Settings Authenticated';
    if (t === 'SECURITY_ALERT_SENT') return 'Security Alert Sent (5 Failures)';
    if (t === 'RECOVERY_REQUESTED') return 'Recovery Code Requested';
    if (t === 'OTP_SENT') return 'Verification OTP Sent';
    if (t === 'OTP_VERIFIED') return 'Recovery OTP Verified';
    if (t === 'OTP_FAILED') return 'Incorrect OTP Attempt';
    if (t === 'OTP_EXPIRED') return 'Recovery OTP Expired';
    if (t === 'RECOVERY_EMAIL_CHANGED') return 'Recovery Email Changed';
    if (t === 'RECOVERY_EMAIL_VERIFIED') return 'Recovery Email Verified';
    if (t === 'FAILED_ATTEMPT' || t === 'UNLOCK_FAILED') return 'Failed Unlock Attempt';
    if (t === 'RESET') return 'Security Settings Reset';
    return defaultDesc || 'Security Event';
  }

  function formatEventTime(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    const now = new Date();
    const isToday = d.toDateString() === now.toDateString();
    
    const yesterday = new Date();
    yesterday.setDate(now.getDate() - 1);
    const isYesterday = d.toDateString() === yesterday.toDateString();

    const timeStr = d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

    if (isToday) {
      return `Today · ${timeStr}`;
    }
    if (isYesterday) {
      return `Yesterday · ${timeStr}`;
    }
    const dateStr = d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    return `${dateStr} · ${timeStr}`;
  }

  function formatLogTime(ts) {
    return formatEventTime(ts);
  }

  if (clearLogsBtn) {
    clearLogsBtn.addEventListener('click', () => {
      requireSecurityProtection(() => {
        chrome.runtime.sendMessage({ type: 'CLEAR_SECURITY_LOGS' }, () => {
          loadSecurityLogs();
          showToast('Activity log cleared.');
        });
      });
    });
  }

  // ---------------------------------------------------------------------------
  // MODAL 5: DANGER ZONE: RESET SECURITY (Section 12)
  // ---------------------------------------------------------------------------

  openResetSecurityModalBtn.addEventListener('click', () => {
    resetCredentialInput.value = '';
    resetModalAlert.style.display = 'none';
    resetSecurityModal.style.display = 'flex';
    resetCredentialInput.focus();
  });

  function closeResetModal() {
    resetSecurityModal.style.display = 'none';
    resetCredentialInput.value = '';
  }

  if (closeResetModalX) closeResetModalX.addEventListener('click', closeResetModal);
  if (closeResetModalBtn) closeResetModalBtn.addEventListener('click', closeResetModal);

  resetSecurityForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    resetModalAlert.style.display = 'none';

    const entered = resetCredentialInput.value.trim();
    if (!entered) {
      showResetAlert('Please enter your credential to authorize reset.', 'alert-error');
      resetCredentialInput.focus();
      return;
    }

    confirmResetSecurityBtn.disabled = true;
    confirmResetSecurityBtn.textContent = 'Resetting...';

    try {
      const isValid = await verifyCredential(entered);
      if (!isValid) {
        showResetAlert('Incorrect password or PIN. Reset aborted.', 'alert-error');
        resetCredentialInput.value = '';
        resetCredentialInput.focus();
        return;
      }

      chrome.runtime.sendMessage({ type: 'RESET_SECURITY' }, (resp) => {
        if (resp && resp.success) {
          resetSecurityModal.style.display = 'none';
          showToast('Security settings reset successfully.');
          setTimeout(() => {
            window.location.href = 'setup.html';
          }, 600);
        } else {
          showResetAlert('Reset failed. Please try again.', 'alert-error');
        }
      });

    } catch {
      showResetAlert('Error executing reset.', 'alert-error');
    } finally {
      confirmResetSecurityBtn.disabled = false;
      confirmResetSecurityBtn.textContent = 'Reset Security';
    }
  });

  function showResetAlert(msg, className) {
    resetModalAlert.textContent = msg;
    resetModalAlert.className = `alert-box ${className}`;
    resetModalAlert.style.display = 'block';
  }

  // ---------------------------------------------------------------------------
  // Global Toast Helper
  // ---------------------------------------------------------------------------

  let toastTimeout = null;
  function showToast(msg) {
    toastBox.textContent = msg;
    toastBox.style.display = 'block';
    if (toastTimeout) clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
      toastBox.style.display = 'none';
    }, 2800);
  }
});
