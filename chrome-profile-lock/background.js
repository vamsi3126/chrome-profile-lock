/**
 * Chrome Profile Lock - Background Service Worker (Manifest V3)
 *
 * ============================================================================
 * SECURITY AUDIT IMPLEMENTATION & ARCHITECTURAL BOUNDARIES:
 * ============================================================================
 * 1. Sender Authentication for Unlock Requests:
 *    To prevent malicious content scripts or hostile web pages from forging
 *    `UNLOCK_REQUEST` messages, the service worker verifies that `sender.url`
 *    strictly originates from the extension's own `lock.html` page.
 *
 * 2. Comprehensive Internal Page Containment:
 *    Chrome prohibits content script execution on `chrome://` pages by design.
 *    To prevent unauthorized snooping on `chrome://history`, `chrome://downloads`,
 *    `chrome://bookmarks`, or `chrome://extensions`, this service worker
 *    intercepts all navigation to internal browser pages while locked and
 *    redirects them directly to `lock.html`.
 *
 * 3. Multi-Window & Incognito Enforcement:
 *    Monitors `chrome.windows.onCreated` and `chrome.tabs.onCreated` across both
 *    normal and incognito windows (using `incognito: spanning`), ensuring newly
 *    spawned windows immediately respect the lock state.
 *
 * 4. Manifest V3 Service Worker Lifecycle & Auto-Locking:
 *    Uses non-persistent service workers and native `chrome.alarms` to enforce
 *    idle timeouts without keeping an unneeded persistent background page.
 *
 * 5. OS-Level Boundary Disclaimer:
 *    An extension executes inside Chrome's web application sandbox after a
 *    profile is selected. It cannot alter the native OS profile chooser or
 *    protect against users with direct OS filesystem access, memory inspection,
 *    or the `--disable-extensions` command line flag.
 * ============================================================================
 */

// ---------------------------------------------------------------------------
// 1. Storage Keys, Constants & Session Setup
// ---------------------------------------------------------------------------
const STORAGE_KEYS = {
  PASSWORD_HASH: 'passwordHash',
  PASSWORD_SALT: 'salt',
  SETUP_COMPLETE: 'setupComplete',
  PROFILE_NAME: 'cpl_profile_name',
  SETTINGS: 'cpl_settings',
  SESSION_LOCK: 'isLocked',
  LAST_ACTIVE: 'lastActiveTime'
};

const AUTO_LOCK_ALARM = 'CPL_AUTO_LOCK_ALARM';
const AUTO_LOCK_WARN_ALARM = 'CPL_AUTO_LOCK_WARN_ALARM';
const DEFAULT_AUTO_LOCK_MINUTES = 10; // Default: 10 minutes

// Enable content scripts to inspect session storage where supported
if (chrome.storage && chrome.storage.session && chrome.storage.session.setAccessLevel) {
  chrome.storage.session.setAccessLevel({
    accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS'
  }).catch(() => {});
}

// ---------------------------------------------------------------------------
// 2. Lifecycle Listeners: Default to Locked on Startup
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[ChromeProfileLock] Extension installed/updated:', details.reason);

  // Register or unregister Right-Click Context Menu Quick Lock based on settings
  const installSettingsData = await chrome.storage.local.get([STORAGE_KEYS.SETTINGS, 'settings']);
  const installSettings = installSettingsData[STORAGE_KEYS.SETTINGS] || installSettingsData.settings || {};
  await syncContextMenu(installSettings.enableContextMenuLock !== false);

  const isConfigured = await checkIsConfigured();
  if (!isConfigured) {
    console.log('[ChromeProfileLock] No password configured. Launching setup onboarding...');
    chrome.tabs.create({ url: chrome.runtime.getURL('setup.html') });
  } else {
    // Lock profile by default upon installation/update
    await lockProfile();
  }
  await initSystemIdleDetection();
  getProfileUserInfo().catch(() => {});
});

chrome.runtime.onStartup.addListener(async () => {
  console.log('[ChromeProfileLock] Profile startup detected.');
  getProfileUserInfo().catch(() => {});

  const isConfigured = await checkIsConfigured();
  if (!isConfigured) {
    chrome.tabs.create({ url: chrome.runtime.getURL('setup.html') });
    return;
  }

  const settingsData = await chrome.storage.local.get([STORAGE_KEYS.SETTINGS, 'settings', 'lockOnStartup']);
  const settings = settingsData[STORAGE_KEYS.SETTINGS] || settingsData.settings;
  const shouldLockOnStartup = settingsData.lockOnStartup !== false && (!settings || settings.lockOnStartup !== false);

  if (shouldLockOnStartup) {
    await lockProfile();
    await logSecurityEvent('Profile locked on browser startup', 'STARTUP_LOCK');
  } else {
    await unlockProfile();
  }
  await initSystemIdleDetection();

  // Sync right-click context menu setting
  const startupSettings = settingsData[STORAGE_KEYS.SETTINGS] || settingsData.settings || {};
  await syncContextMenu(startupSettings.enableContextMenuLock !== false);
});

// ---------------------------------------------------------------------------
// 3. Auto-Lock Alarms & Activity Tracking (MV3 Compatible)
// ---------------------------------------------------------------------------

/**
 * Retrieves configured auto-lock timeout in minutes (default: 10, 0 = Never).
 * Respects the "Lock when browser becomes inactive" preference.
 */
async function getAutoLockMinutes() {
  const data = await chrome.storage.local.get([STORAGE_KEYS.SETTINGS, 'settings']);
  const settings = data[STORAGE_KEYS.SETTINGS] || data.settings;
  if (settings) {
    if (settings.lockOnInactive === false) {
      return 0; // Disabled when inactivity lock toggle is unchecked
    }
    if (settings.autoLockMinutes !== undefined) {
      return parseInt(settings.autoLockMinutes, 10);
    }
  }
  return DEFAULT_AUTO_LOCK_MINUTES;
}

/**
 * Schedules or resets the auto-lock alarm using Chrome's native alarm scheduler.
 */
async function scheduleAutoLockAlarm() {
  const minutes = await getAutoLockMinutes();
  if (minutes <= 0) {
    // Auto-lock disabled ("Never")
    chrome.alarms.clear(AUTO_LOCK_ALARM);
    chrome.alarms.clear(AUTO_LOCK_WARN_ALARM);
    return;
  }

  // Set/re-arm alarm in Chrome's native alarm system
  chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: minutes });

  // Schedule pre-lock warning 15 seconds (0.25 mins) before lock if timeout is at least 1 min
  if (minutes >= 1) {
    const warnDelay = Math.max(0.1, minutes - 0.25);
    chrome.alarms.create(AUTO_LOCK_WARN_ALARM, { delayInMinutes: warnDelay });
  } else {
    chrome.alarms.clear(AUTO_LOCK_WARN_ALARM);
  }
}

/**
 * Handles alarm triggers for warning toast and final inactivity timeout.
 */
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === AUTO_LOCK_WARN_ALARM) {
    const isLocked = await checkIsLocked();
    if (isLocked) return;

    const data = await chrome.storage.local.get([STORAGE_KEYS.SETTINGS, 'settings']);
    const settings = data[STORAGE_KEYS.SETTINGS] || data.settings;
    if (settings && settings.showInactivityWarning === false) return;

    // Send warning to active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].id) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'SHOW_INACTIVITY_WARNING',
          secondsRemaining: 15
        }).catch(() => {});
      }
    });
    return;
  }

  if (alarm.name !== AUTO_LOCK_ALARM) return;

  const isLocked = await checkIsLocked();
  if (isLocked) {
    chrome.alarms.clear(AUTO_LOCK_ALARM);
    chrome.alarms.clear(AUTO_LOCK_WARN_ALARM);
    return;
  }

  const minutes = await getAutoLockMinutes();
  if (minutes <= 0) return;

  const sessionData = await chrome.storage.session.get([STORAGE_KEYS.LAST_ACTIVE]);
  const lastActive = sessionData[STORAGE_KEYS.LAST_ACTIVE] || 0;
  const elapsedMs = Date.now() - lastActive;
  const timeoutMs = minutes * 60 * 1000;

  // If full inactivity duration elapsed (with 5s buffer), lock the profile
  if (elapsedMs >= timeoutMs - 5000) {
    console.log('[ChromeProfileLock] Inactivity timeout reached. Auto-locking profile across all tabs.');
    await lockProfile();
    chrome.alarms.clear(AUTO_LOCK_ALARM);
    chrome.alarms.clear(AUTO_LOCK_WARN_ALARM);
  } else {
    // Re-arm for remaining duration
    const remainingMinutes = (timeoutMs - elapsedMs) / 60000;
    chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: Math.max(0.5, remainingMinutes) });
  }
});

// ---------------------------------------------------------------------------
// 3b. Chrome System Idle Detection (chrome.idle API)
// ---------------------------------------------------------------------------

async function getSystemIdleSettings() {
  const data = await chrome.storage.local.get([
    'systemIdleLock',
    'systemIdleTimeout',
    STORAGE_KEYS.SETTINGS,
    'settings'
  ]);
  const settings = data[STORAGE_KEYS.SETTINGS] || data.settings || {};
  
  const isEnabled = data.systemIdleLock !== undefined ? Boolean(data.systemIdleLock) : (settings.systemIdleLock !== false);
  const timeoutSecs = data.systemIdleTimeout || settings.systemIdleTimeout || 600; // Default: 600s (10 min)
  
  const clampedTimeout = Math.max(60, Math.min(3600, parseInt(timeoutSecs, 10)));
  return { isEnabled, timeoutSecs: clampedTimeout };
}

async function initSystemIdleDetection() {
  if (!chrome.idle) return;
  const { isEnabled, timeoutSecs } = await getSystemIdleSettings();
  console.log(`[ChromeProfileLock] Initializing system idle detection: enabled=${isEnabled}, timeout=${timeoutSecs}s`);
  try {
    chrome.idle.setDetectionInterval(timeoutSecs);
  } catch (err) {
    console.warn('[ChromeProfileLock] Failed to set idle detection interval:', err);
  }
}

if (chrome.idle && chrome.idle.onStateChanged) {
  chrome.idle.onStateChanged.addListener(async (newState) => {
    console.log('[ChromeProfileLock] System idle state changed to:', newState);
    if (newState === 'idle' || newState === 'locked') {
      const isConfigured = await checkIsConfigured();
      if (!isConfigured) return;

      const { isEnabled } = await getSystemIdleSettings();
      if (!isEnabled) return;

      const isLocked = await checkIsLocked();
      if (!isLocked) {
        console.log('[ChromeProfileLock] System idle timeout reached. Engaging profile lock.');
        await lockProfile();
        await logSecurityEvent('Profile locked due to system idle', 'IDLE_LOCK');
      }
    } else if (newState === 'active') {
      // CRITICAL: When the user becomes active again, DO NOT automatically unlock the profile!
      // The user must authenticate.
      console.log('[ChromeProfileLock] System active again. Profile remains locked until authenticated.');
    }
  });
}

/**
 * Updates last active timestamp and postpones auto-lock alarm.
 */
async function handleUserActivity() {
  const isLocked = await checkIsLocked();
  if (isLocked) return;

  const now = Date.now();
  await chrome.storage.session.set({ [STORAGE_KEYS.LAST_ACTIVE]: now });
  await scheduleAutoLockAlarm();
}

// ---------------------------------------------------------------------------
// 4. Tab, Window & Internal Page Monitoring (Security Audit Fixes 11, 12, 15)
// ---------------------------------------------------------------------------

/**
 * Identifies pages where content scripts cannot execute and where user data
 * (history, downloads, bookmarks) could be leaked while locked.
 */
function isRestrictedInternalUrl(url) {
  if (!url) return true; // blank/new tab
  // Allow our own extension pages (lock, setup, options)
  if (url.startsWith(chrome.runtime.getURL(''))) {
    return false;
  }
  return (
    url.startsWith('chrome://') ||
    url.startsWith('chrome-search://') ||
    url.startsWith('about:') ||
    url.startsWith('view-source:') ||
    url.includes('chromewebstore.google.com') ||
    url.includes('chrome.google.com/webstore')
  );
}

/**
 * Intercepts new tab creation when profile is locked.
 */
chrome.tabs.onCreated.addListener(async (tab) => {
  const isConfigured = await checkIsConfigured();
  if (!isConfigured) return;

  const isLocked = await checkIsLocked();
  if (isLocked) {
    const url = tab.url || tab.pendingUrl || '';
    if (isRestrictedInternalUrl(url)) {
      chrome.tabs.update(tab.id, { url: chrome.runtime.getURL('lock.html') });
    }
  }
});

/**
 * Intercepts navigation on existing tabs when profile is locked.
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    const isConfigured = await checkIsConfigured();
    if (!isConfigured) return;

    const isLocked = await checkIsLocked();
    if (isLocked) {
      const url = changeInfo.url || tab.url || '';
      if (isRestrictedInternalUrl(url)) {
        chrome.tabs.update(tabId, { url: chrome.runtime.getURL('lock.html') });
      }
    }
  }
});

/**
 * Intercepts new window creation (normal or incognito) when profile is locked.
 */
if (chrome.windows && chrome.windows.onCreated) {
  chrome.windows.onCreated.addListener(async (win) => {
    const isConfigured = await checkIsConfigured();
    if (!isConfigured) return;

    const isLocked = await checkIsLocked();
    if (isLocked && win.id) {
      chrome.tabs.query({ windowId: win.id }, (tabs) => {
        if (tabs && tabs.length) {
          tabs.forEach((t) => {
            if (isRestrictedInternalUrl(t.url || '')) {
              chrome.tabs.update(t.id, { url: chrome.runtime.getURL('lock.html') });
            }
          });
        }
      });
    }
  });
}

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const isLocked = await checkIsLocked();
  if (!isLocked) {
    await handleUserActivity();
  } else {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
      if (tab && isRestrictedInternalUrl(tab.url || '')) {
        chrome.tabs.update(tab.id, { url: chrome.runtime.getURL('lock.html') });
      }
    });
  }
});

// Toolbar icon click
if (chrome.action && chrome.action.onClicked) {
  chrome.action.onClicked.addListener(async () => {
    const isConfigured = await checkIsConfigured();
    if (!isConfigured) {
      chrome.tabs.create({ url: chrome.runtime.getURL('setup.html') });
    } else {
      const isLocked = await checkIsLocked();
      if (isLocked) {
        chrome.tabs.create({ url: chrome.runtime.getURL('lock.html') });
      } else {
        chrome.runtime.openOptionsPage();
      }
    }
  });
}

// Global keyboard shortcut listener (Ctrl+Shift+L / Command+Shift+L)
if (chrome.commands && chrome.commands.onCommand) {
  chrome.commands.onCommand.addListener(async (command) => {
    if (command === 'lock-profile') {
      const isConfigured = await checkIsConfigured();
      if (isConfigured) {
        console.log('[ChromeProfileLock] Global shortcut triggered (Ctrl+Shift+L): Engaging lock.');
        await lockProfile();
        await logSecurityEvent('Profile locked via keyboard shortcut (Ctrl+Shift+L)', 'MANUAL_LOCK');
      }
    }
  });
}

// Right-click context menu listener
if (chrome.contextMenus && chrome.contextMenus.onClicked) {
  chrome.contextMenus.onClicked.addListener(async (info) => {
    if (info.menuItemId === 'cpl_quick_lock') {
      const isConfigured = await checkIsConfigured();
      if (isConfigured) {
        console.log('[ChromeProfileLock] Context menu quick lock triggered.');
        await lockProfile();
        await logSecurityEvent('Profile locked via right-click context menu', 'MANUAL_LOCK');
      }
    }
  });
}

/**
 * Synchronize the browser right-click context menu item.
 * When enabled, provides a quick "Lock Chrome Profile Now" context menu on web pages.
 * When disabled, removes the item cleanly.
 */
async function syncContextMenu(enabled) {
  if (!chrome.contextMenus) return;
  chrome.contextMenus.removeAll(() => {
    if (enabled) {
      chrome.contextMenus.create({
        id: 'cpl_quick_lock',
        title: '🔒 Lock Chrome Profile Now',
        contexts: ['all']
      });
    }
  });
}

// ---------------------------------------------------------------------------
// 5. Runtime Message Dispatcher & Sender Verification (Security Audit Fix 9)
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'CHECK_LOCK_STATE':
      handleCheckLockState(sendResponse);
      return true;

    case 'USER_ACTIVITY':
      handleUserActivity();
      sendResponse({ received: true });
      return false;

    case 'UPDATE_SETTINGS':
      handleUpdateSettings(message.payload, sendResponse);
      return true;

    case 'GET_STATUS':
      handleGetStatus(sendResponse);
      return true;

    case 'SETUP_COMPLETE':
      handleSetupComplete(message.payload, sender, sendResponse);
      return true;

    case 'UNLOCK_REQUEST':
      handleUnlockRequest(message.payload, sender, sendResponse);
      return true;

    case 'LOCK_PROFILE':
      handleLockProfile(sendResponse);
      return true;

    case 'LOG_SECURITY_EVENT':
      if (message.payload) {
        logSecurityEvent(message.payload.description, message.payload.type).then(() => {
          sendResponse({ success: true });
        });
        return true;
      }
      sendResponse({ success: false });
      return false;

    case 'GET_SECURITY_LOGS':
      chrome.storage.local.get(['cpl_security_logs'], (data) => {
        sendResponse({ logs: data.cpl_security_logs || [] });
      });
      return true;

    case 'CLEAR_SECURITY_LOGS':
      chrome.storage.local.set({ cpl_security_logs: [] }, () => {
        sendResponse({ success: true });
      });
      return true;

    case 'INCREMENT_BLOCKED_INTRUSION':
      incrementMetric('blockedIntrusions');
      sendResponse({ success: true });
      return true;

    case 'EMERGENCY_CLEAR_TABS':
      handleEmergencyClearTabs(sender, sendResponse);
      return true;

    case 'RESET_SECURITY':
      handleResetSecurity(sendResponse);
      return true;

    case 'GET_PROFILE_IDENTITY':
      getProfileUserInfo().then((userInfo) => {
        sendResponse({ success: true, userInfo });
      });
      return true;

    case 'TRIGGER_SECURITY_ALERT':
      handleTriggerSecurityAlert(message.payload, sendResponse);
      return true;

    default:
      sendResponse({ status: 'unknown_command' });
      return false;
  }
});

// ---------------------------------------------------------------------------
// 6. Core State Handlers & Sender Security
// ---------------------------------------------------------------------------

async function checkIsConfigured() {
  const data = await chrome.storage.local.get([
    STORAGE_KEYS.SETUP_COMPLETE,
    STORAGE_KEYS.PASSWORD_HASH,
    'cpl_password_hash'
  ]);
  return Boolean(
    data[STORAGE_KEYS.SETUP_COMPLETE] &&
    (data[STORAGE_KEYS.PASSWORD_HASH] || data.cpl_password_hash)
  );
}

async function checkIsLocked() {
  const session = await chrome.storage.session.get([
    STORAGE_KEYS.SESSION_LOCK,
    'cpl_session_locked'
  ]);
  return session[STORAGE_KEYS.SESSION_LOCK] !== false && session.cpl_session_locked !== false;
}

/**
 * Visual badge indicator in browser toolbar
 */
async function updateBadge(isLocked) {
  if (!chrome.action || !chrome.action.setBadgeText) return;
  try {
    if (isLocked) {
      await chrome.action.setBadgeText({ text: 'LOC' });
      if (chrome.action.setBadgeBackgroundColor) {
        await chrome.action.setBadgeBackgroundColor({ color: '#ea4335' });
      }
    } else {
      await chrome.action.setBadgeText({ text: '' });
    }
  } catch {
    // Non-blocking
  }
}

const MAX_SECURITY_LOGS = 30;

async function logSecurityEvent(description, eventType = 'info') {
  try {
    const data = await chrome.storage.local.get(['cpl_security_logs']);
    const logs = Array.isArray(data.cpl_security_logs) ? data.cpl_security_logs : [];
    logs.unshift({
      id: Date.now() + '-' + Math.random().toString(36).substring(2, 7),
      timestamp: Date.now(),
      description: description,
      type: eventType
    });
    if (logs.length > MAX_SECURITY_LOGS) {
      logs.length = MAX_SECURITY_LOGS;
    }
    await chrome.storage.local.set({ cpl_security_logs: logs });
  } catch {
    // Non-blocking
  }
}

/**
 * Privacy Feature: Mutes all tabs that are currently playing audio or unmuted.
 */
async function muteAllAudibleTabs() {
  try {
    const data = await chrome.storage.local.get([STORAGE_KEYS.SETTINGS, 'settings']);
    const settings = data[STORAGE_KEYS.SETTINGS] || data.settings;
    if (settings && settings.muteOnLock === false) return;

    chrome.tabs.query({}, async (tabs) => {
      if (!tabs || !tabs.length) return;
      const mutedTabIds = [];
      for (const tab of tabs) {
        if (tab.id && !tab.mutedInfo?.muted) {
          try {
            await chrome.tabs.update(tab.id, { muted: true });
            mutedTabIds.push(tab.id);
          } catch {}
        }
      }
      if (mutedTabIds.length > 0) {
        await chrome.storage.session.set({ cpl_auto_muted_tabs: mutedTabIds });
      }
    });
  } catch {}
}

/**
 * Restores previous audio state on tabs that were auto-muted by lock.
 */
async function restoreTabAudio() {
  try {
    const data = await chrome.storage.session.get(['cpl_auto_muted_tabs']);
    const mutedTabIds = data.cpl_auto_muted_tabs;
    if (Array.isArray(mutedTabIds) && mutedTabIds.length > 0) {
      for (const tabId of mutedTabIds) {
        try {
          await chrome.tabs.update(tabId, { muted: false });
        } catch {}
      }
      await chrome.storage.session.remove(['cpl_auto_muted_tabs']);
    }
  } catch {}
}

async function incrementMetric(metricKey) {
  try {
    const data = await chrome.storage.local.get(['cpl_metrics']);
    const metrics = data.cpl_metrics || {
      totalLocks: 0,
      totalUnlocks: 0,
      blockedIntrusions: 0,
      lastUnlockedTime: 0
    };
    if (metricKey === 'totalLocks') {
      metrics.totalLocks = (metrics.totalLocks || 0) + 1;
    } else if (metricKey === 'totalUnlocks') {
      metrics.totalUnlocks = (metrics.totalUnlocks || 0) + 1;
      metrics.lastUnlockedTime = Date.now();
    } else if (metricKey === 'blockedIntrusions') {
      metrics.blockedIntrusions = (metrics.blockedIntrusions || 0) + 1;
    }
    await chrome.storage.local.set({ cpl_metrics: metrics });
  } catch {}
}

async function handleEmergencyClearTabs(sender, sendResponse) {
  try {
    const targetWinId = sender?.tab?.windowId;
    const queryOptions = targetWinId ? { windowId: targetWinId } : { currentWindow: true };
    chrome.tabs.query(queryOptions, async (tabs) => {
      try {
        const newLockTab = await chrome.tabs.create({ url: chrome.runtime.getURL('lock.html') });
        const toClose = (tabs || []).filter(t => t.id && t.id !== newLockTab.id).map(t => t.id);
        if (toClose.length > 0) {
          await chrome.tabs.remove(toClose);
        }
        await lockProfile();
        await logSecurityEvent('Emergency panic tab cleaner executed', 'alert');
        sendResponse({ success: true });
      } catch {
        sendResponse({ success: false });
      }
    });
  } catch {
    sendResponse({ success: false });
  }
}

/**
 * Engages profile lock across session storage, clears auto-lock alarm,
 * and broadcasts overlay injection to all open tabs.
 */
async function getProfileUserInfo() {
  return new Promise(async (resolve) => {
    let email = '';
    let id = '';

    // 1. Try Chrome Identity API
    if (chrome.identity && chrome.identity.getProfileUserInfo) {
      try {
        await new Promise((cbResolve) => {
          try {
            chrome.identity.getProfileUserInfo({ accountStatus: 'ANY' }, (userInfo) => {
              if (!chrome.runtime.lastError && userInfo && userInfo.email) {
                email = userInfo.email.trim();
                id = userInfo.id || '';
              }
              cbResolve();
            });
          } catch {
            chrome.identity.getProfileUserInfo((userInfo) => {
              if (!chrome.runtime.lastError && userInfo && userInfo.email) {
                email = userInfo.email.trim();
                id = userInfo.id || '';
              }
              cbResolve();
            });
          }
        });
      } catch {
        // Non-blocking
      }
    }

    // 2. Check storage fallback if identity API did not return an email
    if (!email) {
      try {
        const data = await chrome.storage.local.get([
          'cpl_profile_email',
          'profileEmail',
          'cpl_security_email',
          'verifiedSecurityEmail',
          'securityEmail',
          'cpl_recovery_email',
          'recoveryEmail'
        ]);
        email = data.cpl_profile_email || data.profileEmail || data.cpl_security_email || data.verifiedSecurityEmail || data.securityEmail || data.cpl_recovery_email || data.recoveryEmail || '';
        email = typeof email === 'string' ? email.trim() : '';
      } catch {}
    }

    if (email) {
      chrome.storage.local.set({ cpl_profile_email: email }).catch(() => {});
    }

    resolve({ email, id });
  });
}

async function getBackendApiUrl() {
  const data = await chrome.storage.local.get(['cpl_backend_url']);
  return data.cpl_backend_url || 'http://localhost:3000';
}

async function handleTriggerSecurityAlert(payload, sendResponse) {
  try {
    const episodeData = await chrome.storage.session.get(['cpl_alert_sent_for_episode']);
    if (episodeData.cpl_alert_sent_for_episode) {
      sendResponse({ success: false, reason: 'Already sent for this lock episode' });
      return;
    }

    const userInfo = await getProfileUserInfo();
    let targetEmail = userInfo.email;

    if (!targetEmail) {
      const emailData = await chrome.storage.local.get(['cpl_security_email', 'verifiedSecurityEmail', 'securityEmail']);
      targetEmail = emailData.cpl_security_email || emailData.verifiedSecurityEmail || emailData.securityEmail || '';
    }

    if (!targetEmail) {
      console.warn('[ChromeProfileLock] Security alert skipped: No profile or security email configured.');
      await logSecurityEvent('Security alert skipped: No security email configured', 'FAILED_ATTEMPT');
      sendResponse({ success: false, error: 'No security email configured' });
      return;
    }

    const localData = await chrome.storage.local.get(['profileName', 'cpl_profile_name']);
    const profileName = payload?.profileName || localData.profileName || localData.cpl_profile_name || 'Vamsi Greeshma';
    const backendUrl = await getBackendApiUrl();

    // Mark episode as alerted BEFORE network call to prevent duplicate triggers
    await chrome.storage.session.set({ cpl_alert_sent_for_episode: true });

    const res = await fetch(`${backendUrl}/api/security-alert`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: targetEmail,
        profileName: profileName
      })
    });

    if (res.ok) {
      await logSecurityEvent('Security intrusion alert sent to profile email', 'SECURITY_ALERT_SENT');
      sendResponse({ success: true });
    } else {
      await logSecurityEvent('Security alert could not be delivered', 'FAILED_ATTEMPT');
      sendResponse({ success: false, error: 'Security alert could not be delivered.' });
    }
  } catch (err) {
    console.warn('[ChromeProfileLock] Network error sending security alert:', err);
    await logSecurityEvent('Security alert could not be delivered', 'FAILED_ATTEMPT');
    sendResponse({ success: false, error: 'Security alert could not be delivered.' });
  }
}

/**
 * Engages profile lock across session storage, clears auto-lock alarm,
 * and broadcasts overlay injection to all open tabs.
 */
async function lockProfile() {
  console.log('[ChromeProfileLock] Engaging lock state across all tabs...');
  await chrome.storage.session.set({
    [STORAGE_KEYS.SESSION_LOCK]: true,
    cpl_session_locked: true,
    cpl_alert_sent_for_episode: false
  });
  chrome.alarms.clear(AUTO_LOCK_ALARM);
  chrome.alarms.clear(AUTO_LOCK_WARN_ALARM);
  updateBadge(true);
  await muteAllAudibleTabs();
  incrementMetric('totalLocks');
  broadcastLockState(true);
}

/**
 * Releases profile lock across session storage, initializes activity timestamp,
 * arms the auto-lock alarm, and broadcasts overlay removal to all open tabs.
 */
async function unlockProfile() {
  console.log('[ChromeProfileLock] Releasing lock state across all tabs...');
  const now = Date.now();
  await chrome.storage.session.set({
    [STORAGE_KEYS.SESSION_LOCK]: false,
    cpl_session_locked: false,
    cpl_alert_sent_for_episode: false,
    [STORAGE_KEYS.LAST_ACTIVE]: now,
    unlockedAt: now
  });
  await chrome.storage.local.remove([
    'cpl_consecutive_failures',
    'cpl_failed_attempts_while_locked',
    'cpl_lockout_until'
  ]);
  updateBadge(false);
  await restoreTabAudio();
  incrementMetric('totalUnlocks');
  broadcastLockState(false);
  await scheduleAutoLockAlarm();
}

function broadcastLockState(isLocked) {
  chrome.tabs.query({}, (tabs) => {
    if (tabs && tabs.length) {
      tabs.forEach((tab) => {
        if (tab && tab.id) {
          chrome.tabs.sendMessage(tab.id, {
            type: 'LOCK_STATE_CHANGED',
            isLocked: isLocked
          }).catch(() => {});
        }
      });
    }
  });
}

async function handleCheckLockState(sendResponse) {
  const isConfigured = await checkIsConfigured();
  const isLocked = await checkIsLocked();
  const localData = await chrome.storage.local.get([STORAGE_KEYS.PROFILE_NAME, 'profileName']);
  sendResponse({
    isConfigured: isConfigured,
    isLocked: isConfigured && isLocked,
    profileName: localData.profileName || localData[STORAGE_KEYS.PROFILE_NAME] || 'Vamsi Greeshma'
  });
}

function handleGetStatus(sendResponse) {
  handleCheckLockState(sendResponse);
}

async function handleSetupComplete(payload, sender, sendResponse) {
  // Validate sender must be setup.html
  const setupUrl = chrome.runtime.getURL('setup.html');
  if (!sender.url || !sender.url.startsWith(setupUrl)) {
    sendResponse({ success: false, error: 'Unauthorized sender' });
    return;
  }

  console.log('[ChromeProfileLock] Setup marked complete. Locking profile session...');
  await lockProfile();
  await logSecurityEvent('Initial password setup completed', 'setup');
  sendResponse({ success: true });
}

/**
 * Handles unlock request. Strictly validates sender to prevent forged
 * messages from web pages or malicious content scripts.
 */
async function handleUnlockRequest(payload, sender, sendResponse) {
  const lockUrl = chrome.runtime.getURL('lock.html');
  if (!sender.url || !sender.url.startsWith(lockUrl)) {
    console.warn('[ChromeProfileLock] Rejected forged UNLOCK_REQUEST from:', sender.url);
    await logSecurityEvent('Rejected unauthorized UNLOCK_REQUEST attempt', 'alert');
    sendResponse({ success: false, error: 'Unauthorized context' });
    return;
  }

  console.log('[ChromeProfileLock] Unlock confirmed from lock.html. Releasing lock & arming auto-lock alarm...');
  await unlockProfile();
  await logSecurityEvent('Profile unlocked successfully', 'PROFILE_UNLOCKED');
  sendResponse({ success: true, isLocked: false });
}

function handleLockProfile(sendResponse) {
  lockProfile().then(async () => {
    await logSecurityEvent('Profile manually locked', 'MANUAL_LOCK');
    sendResponse({ success: true, isLocked: true });
  });
}

async function handleResetSecurity(sendResponse) {
  try {
    await logSecurityEvent('Security settings and credentials reset', 'RESET');
    
    // Clear credentials and lock metadata
    await chrome.storage.local.remove([
      'passwordHash',
      'salt',
      'cpl_password_hash',
      'cpl_password_salt',
      'cpl_pin_hash',
      'cpl_pin_salt',
      'authCredential',
      'setupComplete',
      'cpl_consecutive_failures',
      'cpl_lockout_until',
      'cpl_failed_attempts_while_locked'
    ]);

    // Reset default settings
    const defaultSettings = {
      authMode: 'password',
      systemIdleLock: true,
      systemIdleTimeout: 600,
      lockOnStartup: true,
      protectSecuritySettings: true,
      autoMute: true,
      showInactivityWarning: true,
      cloakTabTitle: true
    };
    await chrome.storage.local.set({
      settings: defaultSettings,
      cpl_settings: defaultSettings,
      systemIdleLock: true,
      systemIdleTimeout: 600,
      lockOnStartup: true,
      protectSecuritySettings: true
    });

    await unlockProfile();
    sendResponse({ success: true });
  } catch (err) {
    sendResponse({ success: false, error: err.message });
  }
}

async function handleUpdateSettings(payload, sendResponse) {
  console.log('[ChromeProfileLock] Settings updated. Re-evaluating auto-lock and system idle...');
  const isLocked = await checkIsLocked();
  if (!isLocked) {
    await scheduleAutoLockAlarm();
  }
  await initSystemIdleDetection();
  if (payload && payload.enableContextMenuLock !== undefined) {
    await syncContextMenu(Boolean(payload.enableContextMenuLock));
  }
  sendResponse({ success: true });
}
