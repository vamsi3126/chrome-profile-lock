/**
 * Chrome Profile Lock - Password Setup Controller
 *
 * Security Enhancements:
 * - PBKDF2 with HMAC-SHA-256 and 310,000 iterations (OWASP recommendation)
 * - Safe DOM manipulation (zero innerHTML usage)
 * - Cryptographically random 16-byte salt via crypto.getRandomValues
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
  const setupForm = document.getElementById('setupForm');
  const passwordInput = document.getElementById('passwordInput');
  const confirmPasswordInput = document.getElementById('confirmPasswordInput');
  const togglePasswordBtn = document.getElementById('togglePasswordBtn');
  const toggleConfirmPasswordBtn = document.getElementById('toggleConfirmPasswordBtn');
  const showPasswordCheckbox = document.getElementById('showPasswordCheckbox');
  const setupAlert = document.getElementById('setupAlert');
  const createPasswordBtn = document.getElementById('createPasswordBtn');

  // PBKDF2 parameters (OWASP recommendation for PBKDF2-HMAC-SHA256)
  const PBKDF2_ITERATIONS = 310000;
  const HASH_BITS = 256;

  // Check if profile setup is already complete; if so, navigate to lock.html
  chrome.storage.local.get(['setupComplete', 'passwordHash', 'cpl_theme'], (data) => {
    if (data && data.cpl_theme) {
      document.documentElement.setAttribute('data-theme', data.cpl_theme);
    }
    if (data && data.setupComplete && data.passwordHash) {
      window.location.href = 'lock.html';
    }
  });

  // -------------------------------------------------------------------------
  // 1. Password Visibility Toggles (Safe DOM Manipulation - Zero innerHTML)
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

  function setInputVisibility(inputEl, toggleBtn, isVisible) {
    inputEl.setAttribute('type', isVisible ? 'text' : 'password');
    if (toggleBtn) {
      setEyeIconSvg(toggleBtn, isVisible);
      toggleBtn.style.color = isVisible ? '#8ab4f8' : '#9aa0a6';
      toggleBtn.setAttribute('title', isVisible ? 'Hide password' : 'Show password');
    }
  }

  // Individual toggle buttons
  togglePasswordBtn.addEventListener('click', () => {
    const isCurrentlyPassword = passwordInput.getAttribute('type') === 'password';
    setInputVisibility(passwordInput, togglePasswordBtn, isCurrentlyPassword);
    syncGlobalCheckbox();
  });

  toggleConfirmPasswordBtn.addEventListener('click', () => {
    const isCurrentlyPassword = confirmPasswordInput.getAttribute('type') === 'password';
    setInputVisibility(confirmPasswordInput, toggleConfirmPasswordBtn, isCurrentlyPassword);
    syncGlobalCheckbox();
  });

  // Global "Show password" checkbox toggle
  showPasswordCheckbox.addEventListener('change', () => {
    const shouldShow = showPasswordCheckbox.checked;
    setInputVisibility(passwordInput, togglePasswordBtn, shouldShow);
    setInputVisibility(confirmPasswordInput, toggleConfirmPasswordBtn, shouldShow);
  });

  function syncGlobalCheckbox() {
    const pwdShown = passwordInput.getAttribute('type') === 'text';
    const confirmShown = confirmPasswordInput.getAttribute('type') === 'text';
    showPasswordCheckbox.checked = pwdShown && confirmShown;
  }

  // -------------------------------------------------------------------------
  // 2. Web Crypto API: PBKDF2 Password Hashing (310,000 iterations)
  // -------------------------------------------------------------------------

  function generateRandomSalt() {
    const salt = new Uint8Array(16);
    window.crypto.getRandomValues(salt);
    return salt;
  }

  function bufferToHex(buffer) {
    const byteView = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < byteView.length; i++) {
      hex += byteView[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  /**
   * Derives a cryptographic hash using PBKDF2 with HMAC-SHA-256 and 310,000 iterations.
   * Never stores or logs plaintext passwords.
   */
  async function derivePasswordHash(password, salt) {
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
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      baseKey,
      HASH_BITS
    );

    return bufferToHex(derivedBits);
  }

  // -------------------------------------------------------------------------
  // 3. Form Submission & Validation
  // -------------------------------------------------------------------------

  setupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (!password) {
      showError('Please enter a password.');
      passwordInput.focus();
      return;
    }

    if (password.length < 6) {
      showError('Password must be at least 6 characters long.');
      passwordInput.focus();
      return;
    }

    if (!confirmPassword) {
      showError('Please confirm your password.');
      confirmPasswordInput.focus();
      return;
    }

    if (password !== confirmPassword) {
      showError('Passwords do not match. Please verify.');
      confirmPasswordInput.focus();
      return;
    }

    createPasswordBtn.disabled = true;
    createPasswordBtn.textContent = 'Securing Profile...';

    try {
      // 1. Generate unpredictable cryptographically secure 16-byte random salt
      const saltBytes = generateRandomSalt();
      const saltHex = bufferToHex(saltBytes);

      // 2. Derive hash with 310,000 iterations
      const hashHex = await derivePasswordHash(password, saltBytes);

      // 3. Clear plaintext passwords immediately from DOM
      passwordInput.value = '';
      confirmPasswordInput.value = '';

      // 4. Retrieve Chrome profile email if available
      let detectedProfileEmail = '';
      if (chrome.identity && chrome.identity.getProfileUserInfo) {
        try {
          detectedProfileEmail = await new Promise((res) => {
            const timer = setTimeout(() => res(''), 1200);
            try {
              chrome.identity.getProfileUserInfo({ accountStatus: 'ANY' }, (info) => {
                clearTimeout(timer);
                res(info && info.email ? info.email.trim() : '');
              });
            } catch {
              chrome.identity.getProfileUserInfo((info) => {
                clearTimeout(timer);
                res(info && info.email ? info.email.trim() : '');
              });
            }
          });
        } catch {}
      }

      // 5. Store hash, salt, setupComplete and profile email in chrome.storage.local
      const authCredential = {
        mode: 'password',
        hash: hashHex,
        salt: saltHex,
        iterations: PBKDF2_ITERATIONS
      };

      const storagePayload = {
        passwordHash: hashHex,
        salt: saltHex,
        setupComplete: true,
        cpl_password_hash: hashHex,
        cpl_password_salt: saltHex,
        cpl_setup_complete: true,
        authCredential: authCredential,
        authMode: 'password',
        cpl_auth_mode: 'password'
      };

      if (detectedProfileEmail) {
        storagePayload.cpl_profile_email = detectedProfileEmail;
        storagePayload.cpl_recovery_email = detectedProfileEmail;
        storagePayload.cpl_recovery_verified = true;
      }

      await chrome.storage.local.set(storagePayload);

      showSuccess('Password created successfully! Redirecting...');

      // Notify background service worker
      chrome.runtime.sendMessage({ type: 'SETUP_COMPLETE' }, () => {
        if (chrome.runtime.lastError) {
          // ignore
        }
      });

      // Redirect to lock.html
      setTimeout(() => {
        window.location.href = 'lock.html';
      }, 400);

    } catch {
      showError('Failed to generate password hash. Please try again.');
      createPasswordBtn.disabled = false;
      createPasswordBtn.textContent = 'Create Password';
    }
  });

  // -------------------------------------------------------------------------
  // 4. Subtle Alert Helpers (Safe textContent)
  // -------------------------------------------------------------------------

  function showError(msg) {
    setupAlert.textContent = msg;
    setupAlert.className = 'alert-box alert-error';
    setupAlert.style.display = 'block';
  }

  function showSuccess(msg) {
    setupAlert.textContent = msg;
    setupAlert.className = 'alert-box alert-success';
    setupAlert.style.display = 'block';
  }

  function hideAlert() {
    setupAlert.style.display = 'none';
  }
});
