/**
 * Chrome Profile Lock - Lock Screen Controller
 *
 * Security Enhancements:
 * - PBKDF2 with HMAC-SHA-256 and 310,000 iterations (OWASP standard)
 * - Timing-safe constant-time string comparison (timingSafeEqual)
 * - Safe DOM manipulation (zero innerHTML usage)
 * - Sender authenticated unlock requests
 * - Zero plaintext password storage & zero password logging
 */

// ---------------------------------------------------------------------------
// Security: Completely disable right-click context menu & DevTools/inspection
// ---------------------------------------------------------------------------
function suppressContextMenu(e) {
  try {
    e.preventDefault();
    e.stopPropagation();
    if (typeof e.stopImmediatePropagation === 'function') {
      e.stopImmediatePropagation();
    }
  } catch {}
  return false;
}

// Block context menu immediately on window and document in capture phase
window.addEventListener('contextmenu', suppressContextMenu, { capture: true, passive: false });
document.addEventListener('contextmenu', suppressContextMenu, { capture: true, passive: false });

// Block secondary mouse clicks (right-click mousedown/mouseup/auxclick)
['mousedown', 'mouseup', 'auxclick'].forEach((evtType) => {
  window.addEventListener(evtType, (e) => {
    if (e.button === 2) {
      suppressContextMenu(e);
    }
  }, { capture: true, passive: false });
});

// Block developer inspection shortcuts (F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C, Ctrl+U, Ctrl+S)
window.addEventListener('keydown', (e) => {
  if (e.key === 'F12' || e.keyCode === 123) {
    return suppressContextMenu(e);
  }
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && ['I', 'i', 'J', 'j', 'C', 'c'].includes(e.key)) {
    return suppressContextMenu(e);
  }
  if ((e.ctrlKey || e.metaKey) && (e.key === 'u' || e.key === 'U')) {
    return suppressContextMenu(e);
  }
  if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
    return suppressContextMenu(e);
  }
}, { capture: true, passive: false });

document.addEventListener('DOMContentLoaded', async () => {
  const lockForm = document.getElementById('lockForm');
  const passwordInput = document.getElementById('passwordInput');
  const togglePasswordBtn = document.getElementById('togglePasswordBtn');
  const alertBox = document.getElementById('alertBox');
  const alertMessage = document.getElementById('alertMessage');
  const profileNameEl = document.getElementById('profileName');
  const unlockBtn = document.getElementById('unlockBtn');
  const forgotPasswordBtn = document.getElementById('forgotPasswordBtn');
  const forgotModal = document.getElementById('forgotModal');
  const closeModalBtn = document.getElementById('closeModalBtn');
  const resetLockBtn = document.getElementById('resetLockBtn');

  // Enhancements: Clock, Greeting & Security Banners
  const lockTimeEl = document.getElementById('lockTime');
  const lockDateEl = document.getElementById('lockDate');
  const lockGreetingEl = document.getElementById('lockGreeting');
  const breakInBanner = document.getElementById('breakInBanner');
  const breakInText = document.getElementById('breakInText');
  const lockoutBanner = document.getElementById('lockoutBanner');
  const lockoutText = document.getElementById('lockoutText');

  // Stealth & PIN Elements
  const stealthScreensaver = document.getElementById('stealthScreensaver');
  const stealthClock = document.getElementById('stealthClock');
  const stealthDate = document.getElementById('stealthDate');
  const stealthBtn = document.getElementById('stealthBtn');
  const lockAvatarText = document.getElementById('lockAvatarText');
  const defaultLockSvg = document.getElementById('defaultLockSvg');
  const lockSubtitle = document.getElementById('lockSubtitle');
  const pinEntryWrap = document.getElementById('pinEntryWrap');
  const pinDots = document.querySelectorAll('.pin-dot');
  const numericKeypad = document.getElementById('numericKeypad');
  const keypadClearBtn = document.getElementById('keypadClearBtn');
  const keypadBackspaceBtn = document.getElementById('keypadBackspaceBtn');
  const toggleAuthModeBtn = document.getElementById('toggleAuthModeBtn');
  const panicCloseBtn = document.getElementById('panicCloseBtn');

  const PBKDF2_ITERATIONS = 310000;
  const HASH_BITS = 256;
  let lockoutTimer = null;
  let activeAuthMode = 'password';
  let currentPinDigits = '';
  let storedPinHash = null;
  let storedPinSalt = null;

  // -------------------------------------------------------------------------
  // 1. Initial State Check & Metadata Loading
  // -------------------------------------------------------------------------
  await checkSetupAndLoadMetadata();
  initClockAndGreeting();
  initStealthMode();
  initPinKeypad();
  initPanicExit();
  await checkRateLimitAndBreakIn();

  function initClockAndGreeting() {
    function updateClock() {
      const now = new Date();
      const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const dateStr = now.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });

      if (lockTimeEl) lockTimeEl.textContent = timeStr;
      if (lockDateEl) lockDateEl.textContent = dateStr;
      if (stealthClock) stealthClock.textContent = timeStr;
      if (stealthDate) stealthDate.textContent = dateStr;

      if (lockGreetingEl) {
        const hour = now.getHours();
        let greeting = 'Welcome';
        if (hour >= 5 && hour < 12) {
          greeting = 'Good morning';
        } else if (hour >= 12 && hour < 17) {
          greeting = 'Good afternoon';
        } else if (hour >= 17 && hour < 22) {
          greeting = 'Good evening';
        }
        lockGreetingEl.textContent = greeting;
      }
    }

    updateClock();
    setInterval(updateClock, 1000);
  }

  function initStealthMode() {
    let isStealth = false;

    function toggleStealth(forceState) {
      isStealth = typeof forceState === 'boolean' ? forceState : !isStealth;
      if (stealthScreensaver) {
        stealthScreensaver.style.display = isStealth ? 'flex' : 'none';
      }
    }

    if (stealthBtn) {
      stealthBtn.addEventListener('click', () => toggleStealth(true));
    }
    if (stealthScreensaver) {
      stealthScreensaver.addEventListener('click', () => toggleStealth(false));
    }

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        toggleStealth();
      } else if (isStealth) {
        toggleStealth(false);
      }
    });
  }

  function initPanicExit() {
    function executePanic() {
      if (confirm('Emergency Panic: Close all other open background tabs in this window immediately?')) {
        chrome.runtime.sendMessage({ type: 'EMERGENCY_CLEAR_TABS' }, (resp) => {
          if (resp && resp.success) {
            showError('All other background tabs have been closed.');
          }
        });
      }
    }

    if (panicCloseBtn) {
      panicCloseBtn.addEventListener('click', executePanic);
    }

    window.addEventListener('keydown', (e) => {
      if (e.altKey && (e.key === 'p' || e.key === 'P')) {
        e.preventDefault();
        executePanic();
      }
    });
  }

  function initPinKeypad() {
    if (numericKeypad) {
      numericKeypad.addEventListener('click', (e) => {
        const btn = e.target.closest('.keypad-btn');
        if (!btn) return;
        const key = btn.getAttribute('data-key');
        if (key) {
          handlePinInput(key);
        }
      });
    }

    if (keypadClearBtn) {
      keypadClearBtn.addEventListener('click', handlePinClear);
    }
    if (keypadBackspaceBtn) {
      keypadBackspaceBtn.addEventListener('click', handlePinBackspace);
    }

    if (toggleAuthModeBtn) {
      toggleAuthModeBtn.addEventListener('click', () => {
        setAuthMode(activeAuthMode === 'pin' ? 'password' : 'pin');
      });
    }

    // Physical keyboard input for PIN
    window.addEventListener('keydown', (e) => {
      if (activeAuthMode !== 'pin') return;
      if (e.key >= '0' && e.key <= '9') {
        handlePinInput(e.key);
      } else if (e.key === 'Backspace') {
        handlePinBackspace();
      }
    });
  }

  function setAuthMode(mode) {
    activeAuthMode = mode;
    currentPinDigits = '';
    renderPinDots();

    if (mode === 'pin') {
      if (pinEntryWrap) pinEntryWrap.style.display = 'flex';
      if (lockForm) lockForm.style.display = 'none';
      if (lockSubtitle) lockSubtitle.textContent = 'Enter your 6-digit PIN to continue.';
      if (forgotPasswordBtn) forgotPasswordBtn.textContent = 'Forgot PIN?';
      if (toggleAuthModeBtn) {
        toggleAuthModeBtn.style.display = 'inline-block';
        toggleAuthModeBtn.textContent = 'Use Password Instead';
      }
    } else {
      if (pinEntryWrap) pinEntryWrap.style.display = 'none';
      if (lockForm) lockForm.style.display = 'flex';
      if (lockSubtitle) lockSubtitle.textContent = 'Enter your password to continue.';
      if (forgotPasswordBtn) forgotPasswordBtn.textContent = 'Forgot password?';
      if (toggleAuthModeBtn) {
        toggleAuthModeBtn.style.display = storedPinHash ? 'inline-block' : 'none';
        toggleAuthModeBtn.textContent = 'Use PIN Instead';
      }
      passwordInput.focus();
    }
  }

  function renderPinDots(isError = false) {
    pinDots.forEach((dot, index) => {
      if (isError) {
        dot.classList.add('error');
      } else {
        dot.classList.remove('error');
        if (index < currentPinDigits.length) {
          dot.classList.add('filled');
        } else {
          dot.classList.remove('filled');
        }
      }
    });
  }

  async function handlePinInput(digit) {
    if (activeAuthMode !== 'pin' || currentPinDigits.length >= 6) return;
    currentPinDigits += digit;
    renderPinDots();

    if (currentPinDigits.length === 6) {
      await verifyEnteredPin(currentPinDigits);
    }
  }

  function handlePinBackspace() {
    if (activeAuthMode !== 'pin' || currentPinDigits.length === 0) return;
    currentPinDigits = currentPinDigits.slice(0, -1);
    renderPinDots();
  }

  function handlePinClear() {
    if (activeAuthMode !== 'pin') return;
    currentPinDigits = '';
    renderPinDots();
  }

  async function verifyEnteredPin(pin) {
    if (!storedPinHash || !storedPinSalt) {
      showError('PIN not configured. Please use your master password.');
      setAuthMode('password');
      return;
    }

    try {
      const saltBytes = hexToBytes(storedPinSalt);
      const candidateHash = await computeHash(pin, saltBytes);
      const isValid = timingSafeEqual(candidateHash, storedPinHash);

      if (isValid) {
        await unlockProfile();
      } else {
        renderPinDots(true);
        setTimeout(() => {
          currentPinDigits = '';
          renderPinDots(false);
        }, 500);

        const failData = await chrome.storage.local.get(['cpl_consecutive_failures', 'cpl_failed_attempts_while_locked']);
        const failures = (failData.cpl_consecutive_failures || 0) + 1;
        const totalFailed = (failData.cpl_failed_attempts_while_locked || 0) + 1;

        await chrome.storage.local.set({
          cpl_consecutive_failures: failures,
          cpl_failed_attempts_while_locked: totalFailed
        });

        chrome.runtime.sendMessage({
          type: 'LOG_SECURITY_EVENT',
          payload: {
            description: `Failed PIN unlock attempt (${failures} consecutive)`,
            type: 'FAILED_ATTEMPT'
          }
        }).catch(() => {});

        if (failures >= 5) {
          const lockoutUntil = Date.now() + 30000;
          await chrome.storage.local.set({
            cpl_lockout_until: lockoutUntil,
            cpl_consecutive_failures: 0
          });
          chrome.runtime.sendMessage({ type: 'INCREMENT_BLOCKED_INTRUSION' }).catch(() => {});
          chrome.runtime.sendMessage({
            type: 'TRIGGER_SECURITY_ALERT',
            payload: { profileName: profileNameEl ? profileNameEl.textContent : 'Vamsi Greeshma' }
          }).catch(() => {});
          startLockoutCountdown(lockoutUntil);
        }
      }
    } catch {
      currentPinDigits = '';
      renderPinDots(false);
    }
  }

  async function checkRateLimitAndBreakIn() {
    const data = await chrome.storage.local.get(['cpl_lockout_until', 'cpl_failed_attempts_while_locked']);
    const now = Date.now();
    const lockoutUntil = data.cpl_lockout_until || 0;
    const failedCount = data.cpl_failed_attempts_while_locked || 0;

    if (failedCount > 0 && breakInBanner && breakInText) {
      breakInText.textContent = `Notice: ${failedCount} failed unlock attempt${failedCount > 1 ? 's' : ''} detected while locked.`;
      breakInBanner.style.display = 'flex';
    } else if (breakInBanner) {
      breakInBanner.style.display = 'none';
    }

    if (lockoutUntil > now) {
      startLockoutCountdown(lockoutUntil);
    }
  }

  function startLockoutCountdown(lockoutUntil) {
    if (lockoutTimer) clearInterval(lockoutTimer);
    
    passwordInput.disabled = true;
    unlockBtn.disabled = true;
    lockoutBanner.style.display = 'flex';

    function tick() {
      const remainingSecs = Math.max(0, Math.ceil((lockoutUntil - Date.now()) / 1000));
      if (remainingSecs <= 0) {
        clearInterval(lockoutTimer);
        lockoutTimer = null;
        passwordInput.disabled = false;
        unlockBtn.disabled = false;
        lockoutBanner.style.display = 'none';
        if (activeAuthMode === 'password') {
          passwordInput.focus();
        }
      } else {
        lockoutText.textContent = `Too many failed attempts. Try again in ${remainingSecs}s.`;
      }
    }

    tick();
    lockoutTimer = setInterval(tick, 1000);
  }

  async function checkSetupAndLoadMetadata() {
    chrome.storage.local.get([
      'setupComplete',
      'passwordHash',
      'profileName',
      'cpl_profile_name',
      'cpl_password_hash',
      'cpl_profile_avatar',
      'cpl_auth_mode',
      'cpl_pin_hash',
      'cpl_pin_salt',
      'cpl_theme',
      'authCredential',
      'authMode'
    ], (data) => {
      // Apply theme
      const theme = data.cpl_theme || 'chrome';
      document.documentElement.setAttribute('data-theme', theme);
      const hasHash = Boolean(
        data.passwordHash ||
        data.cpl_password_hash ||
        (data.authCredential && data.authCredential.hash)
      );
      const isComplete = Boolean(data.setupComplete);

      if (!isComplete || !hasHash) {
        window.location.href = 'setup.html';
        return;
      }

      const profileName = data.profileName || data.cpl_profile_name || 'Vamsi Greeshma';
      if (profileNameEl) {
        profileNameEl.textContent = profileName;
      }

      // Render Avatar / Monogram
      const avatar = data.cpl_profile_avatar || data.avatar || 'monogram';
      if (avatar === 'default') {
        if (defaultLockSvg) defaultLockSvg.style.display = 'block';
        if (lockAvatarText) lockAvatarText.style.display = 'none';
      } else if (avatar === 'monogram') {
        const initials = profileName.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase() || 'VG';
        if (lockAvatarText) {
          lockAvatarText.textContent = initials;
          lockAvatarText.style.display = 'flex';
        }
        if (defaultLockSvg) defaultLockSvg.style.display = 'none';
      } else {
        // Emoji avatar
        if (lockAvatarText) {
          lockAvatarText.textContent = avatar;
          lockAvatarText.style.display = 'flex';
        }
        if (defaultLockSvg) defaultLockSvg.style.display = 'none';
      }

      // Check PIN mode
      storedPinHash = data.cpl_pin_hash || (data.authCredential && data.authCredential.mode === 'pin' ? data.authCredential.hash : null);
      storedPinSalt = data.cpl_pin_salt || (data.authCredential && data.authCredential.mode === 'pin' ? data.authCredential.salt : null);

      const resolvedAuthMode = data.authMode || data.cpl_auth_mode || (data.authCredential ? data.authCredential.mode : 'password');
      if (resolvedAuthMode === 'pin' && storedPinHash) {
        setAuthMode('pin');
      } else {
        setAuthMode('password');
      }
    });
  }

  // -------------------------------------------------------------------------
  // 2. Password Visibility Toggle (Safe DOM Manipulation - Zero innerHTML)
  // -------------------------------------------------------------------------
  function setEyeIconSvg(btnEl, isSlashed) {
    while (btnEl.firstChild) {
      btnEl.removeChild(btnEl.firstChild);
    }
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '18');
    svg.setAttribute('height', '18');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');

    if (isSlashed) {
      const path1 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path1.setAttribute('d', 'M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24');
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', '1');
      line.setAttribute('y1', '1');
      line.setAttribute('x2', '23');
      line.setAttribute('y2', '23');
      svg.appendChild(path1);
      svg.appendChild(line);
    } else {
      const path1 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path1.setAttribute('d', 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8z');
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '12');
      circle.setAttribute('cy', '12');
      circle.setAttribute('r', '3');
      svg.appendChild(path1);
      svg.appendChild(circle);
    }
    btnEl.appendChild(svg);
  }

  togglePasswordBtn.addEventListener('click', () => {
    const isCurrentlyPassword = passwordInput.getAttribute('type') === 'password';
    passwordInput.setAttribute('type', isCurrentlyPassword ? 'text' : 'password');
    setEyeIconSvg(togglePasswordBtn, isCurrentlyPassword);
    togglePasswordBtn.style.color = isCurrentlyPassword ? '#8ab4f8' : '#9aa0a6';
    togglePasswordBtn.setAttribute('title', isCurrentlyPassword ? 'Hide password' : 'Show password');
  });

  // -------------------------------------------------------------------------
  // 3. Web Crypto API Key Derivation & Constant-Time Comparison
  // -------------------------------------------------------------------------

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

  /**
   * Constant-time string comparison to prevent timing side-channel attacks.
   */
  function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) {
      mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return mismatch === 0;
  }

  // -------------------------------------------------------------------------
  // 4. Form Submission & Authentication
  // -------------------------------------------------------------------------
  lockForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();

    const enteredPassword = passwordInput.value;
    if (!enteredPassword) {
      showError('Please enter your password.');
      passwordInput.focus();
      return;
    }

    unlockBtn.disabled = true;
    unlockBtn.textContent = 'Verifying...';

    try {
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
        showError('Incorrect password');
        passwordInput.value = '';
        unlockBtn.disabled = false;
        unlockBtn.textContent = 'Unlock';
        return;
      }

      const saltBytes = hexToBytes(storedSalt);
      const computedHash = await computeHash(enteredPassword, saltBytes);

      // Clear password field immediately
      passwordInput.value = '';

      // Secure comparison
      const isValid = timingSafeEqual(computedHash, storedHash);

      if (isValid) {
        await unlockProfile();
      } else {
        const failData = await chrome.storage.local.get(['cpl_consecutive_failures', 'cpl_failed_attempts_while_locked']);
        const failures = (failData.cpl_consecutive_failures || 0) + 1;
        const totalFailed = (failData.cpl_failed_attempts_while_locked || 0) + 1;

        await chrome.storage.local.set({
          cpl_consecutive_failures: failures,
          cpl_failed_attempts_while_locked: totalFailed
        });

        chrome.runtime.sendMessage({
          type: 'LOG_SECURITY_EVENT',
          payload: {
            description: `Failed password unlock attempt (${failures} consecutive)`,
            type: 'FAILED_ATTEMPT'
          }
        }).catch(() => {});

        if (failures >= 5) {
          const lockoutUntil = Date.now() + 30000;
          await chrome.storage.local.set({
            cpl_lockout_until: lockoutUntil,
            cpl_consecutive_failures: 0
          });
          chrome.runtime.sendMessage({ type: 'INCREMENT_BLOCKED_INTRUSION' }).catch(() => {});
          chrome.runtime.sendMessage({
            type: 'LOG_SECURITY_EVENT',
            payload: {
              description: 'Brute-force protection: 30-second lockout engaged after 5 consecutive failures',
              type: 'alert'
            }
          }).catch(() => {});
          chrome.runtime.sendMessage({
            type: 'TRIGGER_SECURITY_ALERT',
            payload: { profileName: profileNameEl ? profileNameEl.textContent : 'Vamsi Greeshma' }
          }).catch(() => {});
          startLockoutCountdown(lockoutUntil);
        } else {
          showError('Incorrect password');
          passwordInput.focus();
          unlockBtn.disabled = false;
          unlockBtn.textContent = 'Unlock';
        }
      }

    } catch {
      passwordInput.value = '';
      showError('Incorrect password');
      unlockBtn.disabled = false;
      unlockBtn.textContent = 'Unlock';
    }
  });

  // -------------------------------------------------------------------------
  // 5. Unlock & Navigation Logic
  // -------------------------------------------------------------------------
  async function unlockProfile() {
    unlockBtn.textContent = 'Unlocked';

    // Clear failure counters and break-in indicator upon successful unlock
    await chrome.storage.local.remove([
      'cpl_consecutive_failures',
      'cpl_lockout_until',
      'cpl_failed_attempts_while_locked'
    ]);

    await chrome.storage.session.set({
      isLocked: false,
      cpl_session_locked: false,
      unlockedAt: Date.now()
    });

    // Notify background service worker (sender verified in background.js)
    chrome.runtime.sendMessage({ type: 'UNLOCK_REQUEST' }, () => {
      if (chrome.runtime.lastError) {
        // ignore
      }
    });

    // If running in an overlay iframe, postMessage to parent content script
    if (window.self !== window.top) {
      window.parent.postMessage({ type: 'CPL_UNLOCKED' }, '*');
    } else {
      await redirectToDestination();
    }
  }

  async function redirectToDestination() {
    const urlParams = new URLSearchParams(window.location.search);
    const returnTo = urlParams.get('returnTo');

    const sessionData = await chrome.storage.session.get(['intendedUrl']);
    const targetUrl = returnTo || sessionData.intendedUrl;

    if (sessionData.intendedUrl) {
      await chrome.storage.session.remove(['intendedUrl']);
    }

    const safeDestination = (targetUrl && isSafeUrl(targetUrl))
      ? targetUrl
      : 'https://www.google.com';

    if (chrome.tabs && chrome.tabs.getCurrent) {
      chrome.tabs.getCurrent((tab) => {
        if (tab && tab.id) {
          chrome.tabs.update(tab.id, { url: safeDestination });
        } else {
          window.location.href = safeDestination;
        }
      });
    } else {
      window.location.href = safeDestination;
    }
  }

  function isSafeUrl(url) {
    try {
      const parsed = new URL(url);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // 6. Subtle Error Helpers (Safe textContent)
  // -------------------------------------------------------------------------
  function showError(msg) {
    alertMessage.textContent = msg;
    alertBox.style.display = 'block';
  }

  function hideError() {
    alertBox.style.display = 'none';
  }

  // -------------------------------------------------------------------------
  // 7. Forgot Password Recovery Flow
  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // 7. Secure Cryptographic OTP Recovery Flow (Feature 4)
  // -------------------------------------------------------------------------
  const closeModalX = document.getElementById('closeModalX');
  const closeNoEmailBtn = document.getElementById('closeNoEmailBtn');
  const cancelRecoveryResetBtn = document.getElementById('cancelRecoveryResetBtn');
  const recoveryFinishBtn = document.getElementById('recoveryFinishBtn');

  const recoveryLoadingState = document.getElementById('recoveryLoadingState');
  const recoveryLoadingText = document.getElementById('recoveryLoadingText');
  const recoveryLoadingAlert = document.getElementById('recoveryLoadingAlert');
  const recoveryLoadingActions = document.getElementById('recoveryLoadingActions');
  const recoveryRetryBtn = document.getElementById('recoveryRetryBtn');
  const recoveryCancelLoadingBtn = document.getElementById('recoveryCancelLoadingBtn');

  const recoveryNoEmailState = document.getElementById('recoveryNoEmailState');
  const recoveryManualEmailInput = document.getElementById('recoveryManualEmailInput');
  const recoveryManualEmailAlert = document.getElementById('recoveryManualEmailAlert');
  const continueManualEmailBtn = document.getElementById('continueManualEmailBtn');

  const recoveryStep2 = document.getElementById('recoveryStep2');
  const recoverySentEmailText = document.getElementById('recoverySentEmailText');
  const recoveryOtpInput = document.getElementById('recoveryOtpInput');
  const recoveryOtpTimer = document.getElementById('recoveryOtpTimer');
  const recoveryResendBtn = document.getElementById('recoveryResendBtn');
  const verifyRecoveryOtpBtn = document.getElementById('verifyRecoveryOtpBtn');

  const recoveryStep3 = document.getElementById('recoveryStep3');
  const recoveryResetForm = document.getElementById('recoveryResetForm');
  const recoveryPasswordFields = document.getElementById('recoveryPasswordFields');
  const recoveryPinFields = document.getElementById('recoveryPinFields');
  const recoveryNewPassword = document.getElementById('recoveryNewPassword');
  const recoveryConfirmPassword = document.getElementById('recoveryConfirmPassword');
  const recoveryNewPin = document.getElementById('recoveryNewPin');
  const recoveryConfirmPin = document.getElementById('recoveryConfirmPin');
  const submitRecoveryResetBtn = document.getElementById('submitRecoveryResetBtn');

  const recoveryStep2Alert = document.getElementById('recoveryStep2Alert');
  const recoveryStep3Alert = document.getElementById('recoveryStep3Alert');
  const recoveryStep4 = document.getElementById('recoveryStep4');
  const recoverySuccessSub = document.getElementById('recoverySuccessSub');

  let currentRecoveryRequestId = null;
  let currentRecoveryToken = null;
  let storedRecoveryEmail = null;
  let otpCountdownInterval = null;

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

  async function getBackendUrl() {
    const data = await chrome.storage.local.get(['cpl_backend_url']);
    return data.cpl_backend_url || 'http://localhost:3000';
  }

  function showRecoveryAlert(alertEl, msg) {
    if (!alertEl) return;
    alertEl.textContent = msg;
    alertEl.style.display = 'block';
  }

  function hideRecoveryAlert(alertEl) {
    if (!alertEl) return;
    alertEl.style.display = 'none';
    alertEl.textContent = '';
  }

  function showRecoveryView(view) {
    if (recoveryLoadingState) recoveryLoadingState.style.display = view === 'loading' ? 'block' : 'none';
    if (recoveryNoEmailState) recoveryNoEmailState.style.display = view === 'no-email' ? 'block' : 'none';
    if (recoveryStep2) recoveryStep2.style.display = view === 'step2' ? 'block' : 'none';
    if (recoveryStep3) recoveryStep3.style.display = view === 'step3' ? 'block' : 'none';
    if (recoveryStep4) recoveryStep4.style.display = view === 'step4' ? 'block' : 'none';
  }

  function closeRecoveryModal() {
    forgotModal.style.display = 'none';
    const modalTitle = document.getElementById('modalTitle');
    if (modalTitle) modalTitle.textContent = 'Reset Profile Authentication';
    if (otpCountdownInterval) {
      clearInterval(otpCountdownInterval);
      otpCountdownInterval = null;
    }
    currentRecoveryRequestId = null;
    currentRecoveryToken = null;
    if (recoveryLoadingAlert) hideRecoveryAlert(recoveryLoadingAlert);
    if (recoveryStep2Alert) hideRecoveryAlert(recoveryStep2Alert);
    if (recoveryStep3Alert) hideRecoveryAlert(recoveryStep3Alert);
    if (recoveryManualEmailAlert) hideRecoveryAlert(recoveryManualEmailAlert);
    if (recoveryOtpInput) recoveryOtpInput.value = '';
    if (recoveryNewPassword) recoveryNewPassword.value = '';
    if (recoveryConfirmPassword) recoveryConfirmPassword.value = '';
    if (recoveryNewPin) recoveryNewPin.value = '';
    if (recoveryConfirmPin) recoveryConfirmPin.value = '';
  }

  function startOtpCountdown(seconds = 300) {
    if (otpCountdownInterval) clearInterval(otpCountdownInterval);
    let remaining = seconds;

    function update() {
      const m = Math.floor(remaining / 60);
      const s = remaining % 60;
      if (recoveryOtpTimer) {
        recoveryOtpTimer.textContent = `${m}:${s < 10 ? '0' : ''}${s}`;
      }
      if (remaining <= 0) {
        clearInterval(otpCountdownInterval);
        otpCountdownInterval = null;
        showRecoveryAlert(recoveryStep2Alert, 'Verification code expired. Please request a new code.');
        if (verifyRecoveryOtpBtn) verifyRecoveryOtpBtn.disabled = true;
      }
      remaining--;
    }

    if (verifyRecoveryOtpBtn) verifyRecoveryOtpBtn.disabled = false;
    update();
    otpCountdownInterval = setInterval(update, 1000);
  }

  /**
   * Resolves the profile email automatically by default from:
   * 1. Direct Chrome Identity API (Google profile account logged in Chrome)
   * 2. Background service worker GET_PROFILE_IDENTITY
   * 3. Chrome local storage (cpl_profile_email, profileEmail, cpl_security_email, cpl_recovery_email)
   */
  async function resolveProfileRecoveryEmail() {
    // 1. Direct chrome.identity call if available in extension page
    if (chrome.identity && chrome.identity.getProfileUserInfo) {
      try {
        const userInfo = await new Promise((resolve) => {
          const timer = setTimeout(() => resolve(null), 1500);
          try {
            chrome.identity.getProfileUserInfo({ accountStatus: 'ANY' }, (info) => {
              clearTimeout(timer);
              resolve(info);
            });
          } catch {
            chrome.identity.getProfileUserInfo((info) => {
              clearTimeout(timer);
              resolve(info);
            });
          }
        });
        if (userInfo && userInfo.email && userInfo.email.trim()) {
          const email = userInfo.email.trim();
          chrome.storage.local.set({ cpl_profile_email: email }).catch(() => {});
          return email;
        }
      } catch {}
    }

    // 2. Check background service worker identity
    try {
      const resp = await new Promise((resolve) => {
        const timer = setTimeout(() => resolve(null), 1500);
        chrome.runtime.sendMessage({ type: 'GET_PROFILE_IDENTITY' }, (r) => {
          clearTimeout(timer);
          resolve(r);
        });
      });
      if (resp && resp.userInfo && resp.userInfo.email && resp.userInfo.email.trim()) {
        const email = resp.userInfo.email.trim();
        chrome.storage.local.set({ cpl_profile_email: email }).catch(() => {});
        return email;
      }
    } catch {}

    // 3. Storage fallbacks
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
      const email = data.cpl_profile_email || data.profileEmail || data.cpl_security_email || data.verifiedSecurityEmail || data.securityEmail || data.cpl_recovery_email || data.recoveryEmail;
      if (email && typeof email === 'string' && email.includes('@')) {
        return email.trim();
      }
    } catch {}

    return null;
  }

  // ---------------------------------------------------------------------------
  // Automatic Dispatch: Send OTP via Resend API immediately
  // ---------------------------------------------------------------------------
  async function executeSendOtp(email) {
    showRecoveryView('loading');
    if (recoveryLoadingText) {
      recoveryLoadingText.textContent = `Sending 6-digit verification code to ${maskEmail(email)}...`;
    }
    hideRecoveryAlert(recoveryLoadingAlert);
    if (recoveryLoadingActions) recoveryLoadingActions.style.display = 'none';

    try {
      const backendUrl = await getBackendUrl();
      const res = await fetch(`${backendUrl}/api/request-recovery`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email })
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        showRecoveryAlert(recoveryLoadingAlert, data.error || 'Failed to dispatch verification code via email provider.');
        if (recoveryLoadingActions) recoveryLoadingActions.style.display = 'flex';
        return;
      }

      currentRecoveryRequestId = data.requestId;

      chrome.runtime.sendMessage({
        type: 'LOG_SECURITY_EVENT',
        payload: {
          description: 'Recovery OTP requested for profile email',
          type: 'RECOVERY_REQUESTED'
        }
      }).catch(() => {});

      // Success: Show Enter OTP view directly!
      showRecoveryView('step2');
      const modalTitle = document.getElementById('modalTitle');
      if (modalTitle) modalTitle.textContent = 'Enter Verification Code';
      if (recoverySentEmailText) {
        recoverySentEmailText.textContent = maskEmail(email);
      }
      if (recoveryOtpInput) {
        recoveryOtpInput.value = '';
        setTimeout(() => recoveryOtpInput.focus(), 150);
      }
      startOtpCountdown(data.expiresIn || 300);

    } catch (err) {
      showRecoveryAlert(recoveryLoadingAlert, 'Could not connect to recovery backend server. Make sure the backend server is running on http://localhost:3000.');
      if (recoveryLoadingActions) recoveryLoadingActions.style.display = 'flex';
    }
  }

  // ---------------------------------------------------------------------------
  // Forgot Password Trigger: Automatically retrieve email and send OTP immediately
  // ---------------------------------------------------------------------------
  forgotPasswordBtn.addEventListener('click', async () => {
    hideRecoveryAlert(recoveryLoadingAlert);
    hideRecoveryAlert(recoveryStep2Alert);
    hideRecoveryAlert(recoveryStep3Alert);
    if (recoveryManualEmailAlert) hideRecoveryAlert(recoveryManualEmailAlert);
    if (recoveryLoadingActions) recoveryLoadingActions.style.display = 'none';

    // Open modal directly in loading state
    forgotModal.style.display = 'flex';
    showRecoveryView('loading');
    if (recoveryLoadingText) {
      recoveryLoadingText.textContent = 'Retrieving profile email and sending OTP...';
    }

    // Automatically resolve profile email
    const detectedEmail = await resolveProfileRecoveryEmail();

    if (detectedEmail) {
      storedRecoveryEmail = detectedEmail;
      // Immediately send OTP to that profile email via Resend!
      await executeSendOtp(detectedEmail);
    } else {
      // Fallback: If no email is linked to this Chrome profile, show manual entry
      showRecoveryView('no-email');
      if (recoveryManualEmailInput) {
        recoveryManualEmailInput.value = '';
        setTimeout(() => recoveryManualEmailInput.focus(), 150);
      }
    }
  });

  // Loading error actions
  if (recoveryRetryBtn) {
    recoveryRetryBtn.addEventListener('click', () => {
      if (storedRecoveryEmail) {
        executeSendOtp(storedRecoveryEmail);
      } else {
        showRecoveryView('no-email');
      }
    });
  }

  if (recoveryCancelLoadingBtn) {
    recoveryCancelLoadingBtn.addEventListener('click', closeRecoveryModal);
  }

  // Fallback continue button
  if (continueManualEmailBtn) {
    continueManualEmailBtn.addEventListener('click', () => {
      const email = (recoveryManualEmailInput.value || '').trim();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showRecoveryAlert(recoveryManualEmailAlert, 'Please enter a valid email address.');
        recoveryManualEmailInput.focus();
        return;
      }
      storedRecoveryEmail = email;
      executeSendOtp(email);
    });
  }

  // Resend code button
  if (recoveryResendBtn) {
    recoveryResendBtn.addEventListener('click', () => {
      if (storedRecoveryEmail) {
        executeSendOtp(storedRecoveryEmail);
      }
    });
  }

  // Auto-verify when 6 digits are typed into OTP input
  if (recoveryOtpInput) {
    recoveryOtpInput.addEventListener('input', () => {
      const val = (recoveryOtpInput.value || '').trim();
      if (val.length === 6 && /^\d{6}$/.test(val)) {
        executeVerifyOtp();
      }
    });
  }

  // Verify OTP handler
  async function executeVerifyOtp() {
    const otp = (recoveryOtpInput.value || '').trim();
    if (!otp || otp.length !== 6 || !/^\d{6}$/.test(otp)) {
      showRecoveryAlert(recoveryStep2Alert, 'Please enter a valid 6-digit verification code.');
      recoveryOtpInput.focus();
      return;
    }

    hideRecoveryAlert(recoveryStep2Alert);
    verifyRecoveryOtpBtn.disabled = true;
    verifyRecoveryOtpBtn.textContent = 'Verifying...';

    try {
      const backendUrl = await getBackendUrl();
      const res = await fetch(`${backendUrl}/api/verify-recovery-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requestId: currentRecoveryRequestId,
          otp: otp
        })
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        showRecoveryAlert(recoveryStep2Alert, data.error || 'Incorrect verification code.');
        chrome.runtime.sendMessage({
          type: 'LOG_SECURITY_EVENT',
          payload: {
            description: 'Incorrect recovery OTP entered',
            type: 'OTP_FAILED'
          }
        }).catch(() => {});
        verifyRecoveryOtpBtn.disabled = false;
        verifyRecoveryOtpBtn.textContent = 'Verify OTP';
        return;
      }

      currentRecoveryToken = data.recoveryToken;
      if (otpCountdownInterval) {
        clearInterval(otpCountdownInterval);
        otpCountdownInterval = null;
      }

      chrome.runtime.sendMessage({
        type: 'LOG_SECURITY_EVENT',
        payload: {
          description: 'Recovery OTP verified successfully',
          type: 'OTP_VERIFIED'
        }
      }).catch(() => {});

      // Switch to Step 3: Reset Master Password / PIN
      showRecoveryView('step3');
      if (activeAuthMode === 'pin') {
        recoveryPinFields.style.display = 'block';
        recoveryPasswordFields.style.display = 'none';
        document.getElementById('modalTitle').textContent = 'Reset 6-Digit PIN';
        if (recoveryNewPin) setTimeout(() => recoveryNewPin.focus(), 150);
      } else {
        recoveryPasswordFields.style.display = 'block';
        recoveryPinFields.style.display = 'none';
        document.getElementById('modalTitle').textContent = 'Reset Master Password';
        if (recoveryNewPassword) setTimeout(() => recoveryNewPassword.focus(), 150);
      }

    } catch (err) {
      showRecoveryAlert(recoveryStep2Alert, 'Recovery backend server is currently unreachable.');
    } finally {
      verifyRecoveryOtpBtn.disabled = false;
      verifyRecoveryOtpBtn.textContent = 'Verify OTP';
    }
  }

  verifyRecoveryOtpBtn.addEventListener('click', executeVerifyOtp);

  [closeModalBtn, closeModalX, closeNoEmailBtn, cancelRecoveryResetBtn].forEach((btn) => {
    if (btn) btn.addEventListener('click', closeRecoveryModal);
  });

  forgotModal.addEventListener('click', (e) => {
    if (e.target === forgotModal) closeRecoveryModal();
  });

  // Step 3 -> Step 4: Submit New Credential
  recoveryResetForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideRecoveryAlert(recoveryStep3Alert);

    if (activeAuthMode === 'pin') {
      const pin = (recoveryNewPin.value || '').trim();
      const confirmPin = (recoveryConfirmPin.value || '').trim();

      if (!/^\d{6}$/.test(pin)) {
        showRecoveryAlert(recoveryStep3Alert, 'PIN must be exactly 6 digits.');
        recoveryNewPin.focus();
        return;
      }

      if (pin !== confirmPin) {
        showRecoveryAlert(recoveryStep3Alert, 'PINs do not match.');
        recoveryConfirmPin.focus();
        return;
      }

      submitRecoveryResetBtn.disabled = true;
      submitRecoveryResetBtn.textContent = 'Resetting...';

      try {
        const backendUrl = await getBackendUrl();
        const res = await fetch(`${backendUrl}/api/complete-recovery`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            requestId: currentRecoveryRequestId,
            recoveryToken: currentRecoveryToken
          })
        });

        const data = await res.json();
        if (!res.ok || !data.success) {
          showRecoveryAlert(recoveryStep3Alert, data.error || 'Recovery authorization invalid or expired.');
          submitRecoveryResetBtn.disabled = false;
          submitRecoveryResetBtn.textContent = 'Reset Credential';
          return;
        }

        // Derive PBKDF2 hash for new PIN
        const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
        const saltHex = bufferToHex(saltBytes);
        const hashHex = await computeHash(pin, saltBytes);

        // Update storage
        await chrome.storage.local.set({
          cpl_pin_hash: hashHex,
          cpl_pin_salt: saltHex,
          authCredential: {
            mode: 'pin',
            hash: hashHex,
            salt: saltHex,
            iterations: PBKDF2_ITERATIONS
          },
          cpl_recovery_email: storedRecoveryEmail,
          cpl_recovery_verified: true,
          cpl_profile_email: storedRecoveryEmail
        });

        storedPinHash = hashHex;
        storedPinSalt = saltHex;

        // Clear failures and lockout
        await chrome.storage.local.remove([
          'cpl_consecutive_failures',
          'cpl_failed_attempts_while_locked',
          'cpl_lockout_until'
        ]);

        chrome.runtime.sendMessage({
          type: 'LOG_SECURITY_EVENT',
          payload: {
            description: '6-Digit PIN reset via secure recovery OTP',
            type: 'PIN_RESET'
          }
        }).catch(() => {});

        recoverySuccessSub.textContent = 'Your 6-digit PIN has been reset. You can now unlock your profile.';
        recoveryStep3.style.display = 'none';
        recoveryStep4.style.display = 'block';

      } catch (err) {
        showRecoveryAlert(recoveryStep3Alert, 'An error occurred during reset. Please try again.');
      } finally {
        submitRecoveryResetBtn.disabled = false;
        submitRecoveryResetBtn.textContent = 'Reset Credential';
      }

    } else {
      // Password mode
      const password = recoveryNewPassword.value || '';
      const confirm = recoveryConfirmPassword.value || '';

      if (password.length < 6) {
        showRecoveryAlert(recoveryStep3Alert, 'Password must be at least 6 characters.');
        recoveryNewPassword.focus();
        return;
      }

      if (password !== confirm) {
        showRecoveryAlert(recoveryStep3Alert, 'Passwords do not match.');
        recoveryConfirmPassword.focus();
        return;
      }

      submitRecoveryResetBtn.disabled = true;
      submitRecoveryResetBtn.textContent = 'Resetting...';

      try {
        const backendUrl = await getBackendUrl();
        const res = await fetch(`${backendUrl}/api/complete-recovery`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            requestId: currentRecoveryRequestId,
            recoveryToken: currentRecoveryToken
          })
        });

        const data = await res.json();
        if (!res.ok || !data.success) {
          showRecoveryAlert(recoveryStep3Alert, data.error || 'Recovery authorization invalid or expired.');
          submitRecoveryResetBtn.disabled = false;
          submitRecoveryResetBtn.textContent = 'Reset Credential';
          return;
        }

        // Derive PBKDF2 hash for new password
        const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
        const saltHex = bufferToHex(saltBytes);
        const hashHex = await computeHash(password, saltBytes);

        // Update storage
        await chrome.storage.local.set({
          passwordHash: hashHex,
          salt: saltHex,
          cpl_password_hash: hashHex,
          cpl_password_salt: saltHex,
          authCredential: {
            mode: 'password',
            hash: hashHex,
            salt: saltHex,
            iterations: PBKDF2_ITERATIONS
          },
          cpl_recovery_email: storedRecoveryEmail,
          cpl_recovery_verified: true,
          cpl_profile_email: storedRecoveryEmail
        });

        // Clear failures and lockout
        await chrome.storage.local.remove([
          'cpl_consecutive_failures',
          'cpl_failed_attempts_while_locked',
          'cpl_lockout_until'
        ]);

        chrome.runtime.sendMessage({
          type: 'LOG_SECURITY_EVENT',
          payload: {
            description: 'Master password reset via secure recovery OTP',
            type: 'PASSWORD_RESET'
          }
        }).catch(() => {});

        recoverySuccessSub.textContent = 'Your master password has been reset. You can now unlock your profile.';
        const modalTitle = document.getElementById('modalTitle');
        if (modalTitle) modalTitle.textContent = 'Authentication Reset Complete';
        recoveryStep3.style.display = 'none';
        recoveryStep4.style.display = 'block';

      } catch (err) {
        showRecoveryAlert(recoveryStep3Alert, 'An error occurred during reset. Please try again.');
      } finally {
        submitRecoveryResetBtn.disabled = false;
        submitRecoveryResetBtn.textContent = 'Reset Credential';
      }
    }
  });

  if (recoveryFinishBtn) {
    recoveryFinishBtn.addEventListener('click', async () => {
      closeRecoveryModal();
      await unlockProfile();
    });
  }
});
