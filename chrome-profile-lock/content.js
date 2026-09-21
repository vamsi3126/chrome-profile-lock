/**
 * Chrome Profile Lock - Content Script (Lock Overlay & Activity Tracking)
 *
 * ============================================================================
 * SECURITY & ARCHITECTURAL LIMITATIONS:
 * ============================================================================
 * 1. Native Profile Picker Boundary:
 *    A Chrome extension executes inside Chrome's web extension sandbox and
 *    CANNOT control or intercept Chrome's native OS profile selector or prevent
 *    a user from choosing this profile from the profile menu.
 *
 * 2. In-Browser Privacy Protection Layer:
 *    Instead, this extension implements a browsing lock layer that engages
 *    immediately once the profile is loaded. By default, every browser session
 *    begins locked in chrome.storage.session.
 *
 * 3. Page Containment & Zero-Leakage:
 *    On all normal web pages, this script executes at `document_start` to
 *    instantly place an opaque, maximum z-index (2147483647) overlay covering
 *    100% of the viewport. This stops visual content exposure, blocks user
 *    interaction, and halts scrolling on the underlying page until unlocked.
 *
 * 4. Origin Isolation (Iframe Security):
 *    The lock UI is hosted inside an isolated `chrome-extension://` iframe.
 *    Because of cross-origin boundaries, scripts running on the host webpage
 *    (including any third-party or hostile scripts) CANNOT access, read, or
 *    intercept the master password input entered inside the lock frame.
 *
 * 5. Throttled Activity Tracking for Auto-Lock:
 *    Tracks user presence (mouse movement, clicks, keyboard, scroll, touch)
 *    to support idle auto-locking. To avoid CPU degradation, events use
 *    passive listeners and are throttled so messages are sent to the background
 *    service worker at most once every 25 seconds. Content scripts NEVER
 *    perform continuous writes to chrome.storage.
 * ============================================================================
 */

(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // 1. Restricted URL Filtering (Requirement 6)
  // ---------------------------------------------------------------------------
  function isRestrictedPage() {
    const url = window.location.href;
    const protocol = window.location.protocol;
    return (
      protocol === 'chrome:' ||
      protocol === 'chrome-extension:' ||
      protocol === 'about:' ||
      protocol === 'view-source:' ||
      protocol === 'data:' ||
      url.includes('chromewebstore.google.com') ||
      url.includes('chrome.google.com/webstore')
    );
  }

  if (isRestrictedPage()) {
    return;
  }

  // Element ID constant
  const OVERLAY_ID = 'cpl-lock-overlay-root';
  let isCurrentlyLocked = false;

  // ---------------------------------------------------------------------------
  // 2. Event Interception Handlers (When Locked - Feature 5)
  // ---------------------------------------------------------------------------

  /**
   * Stops user interaction events from bubbling down to the underlying webpage
   * while the overlay is active. Completely blocks mouse, pointer, touch,
   * keyboard, context menu, scrolling, and drag-and-drop interactions.
   */
  function blockPageInteraction(e) {
    if (!isCurrentlyLocked) return;

    // Security Rule: NEVER allow right-click context menu while locked, even inside the lock overlay
    if (e.type === 'contextmenu' || (e.button === 2 && (e.type === 'mousedown' || e.type === 'mouseup' || e.type === 'auxclick'))) {
      try {
        e.preventDefault();
        e.stopPropagation();
        if (typeof e.stopImmediatePropagation === 'function') {
          e.stopImmediatePropagation();
        }
      } catch {}
      return false;
    }

    // Security Rule: NEVER allow DevTools/source inspection keyboard shortcuts while locked
    if (e.type === 'keydown') {
      if (e.key === 'F12' || e.keyCode === 123) {
        try { e.preventDefault(); e.stopPropagation(); } catch {}
        return false;
      }
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && ['I', 'i', 'J', 'j', 'C', 'c'].includes(e.key)) {
        try { e.preventDefault(); e.stopPropagation(); } catch {}
        return false;
      }
      if ((e.ctrlKey || e.metaKey) && (e.key === 'u' || e.key === 'U')) {
        try { e.preventDefault(); e.stopPropagation(); } catch {}
        return false;
      }
      if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
        try { e.preventDefault(); e.stopPropagation(); } catch {}
        return false;
      }
    }

    // Allow interaction only if the event target is inside our overlay root (typing password, clicking unlock)
    const overlay = document.getElementById(OVERLAY_ID);
    if (overlay && (e.target === overlay || overlay.contains(e.target))) {
      return; // allow interaction with lock UI
    }

    // Intercept, stop propagation, and prevent default browser action on the underlying page
    try {
      e.preventDefault();
      e.stopPropagation();
      if (typeof e.stopImmediatePropagation === 'function') {
        e.stopImmediatePropagation();
      }
    } catch {
      // Non-blocking
    }
  }

  const INTERCEPTION_EVENTS = [
    // Keyboard events (stops shortcuts like Ctrl+C, Ctrl+V, Ctrl+A, F5, etc.)
    'keydown', 'keyup', 'keypress',
    // Mouse & Pointer events (stops clicks, double clicks, auxiliary clicks)
    'mousedown', 'mouseup', 'click', 'dblclick', 'auxclick',
    'pointerdown', 'pointerup', 'pointermove', 'pointerover', 'pointerenter',
    // Context menu (stops webpage right-click menu)
    'contextmenu',
    // Scrolling & Zoom
    'wheel', 'scroll',
    // Touch interactions
    'touchstart', 'touchend', 'touchmove', 'touchcancel',
    // Drag & Drop
    'drag', 'dragstart', 'dragend', 'dragover', 'dragenter', 'dragleave', 'drop',
    // Text Selection & Focus
    'selectstart', 'selectionchange', 'focus', 'focusin', 'blur', 'focusout',
    // Clipboard
    'copy', 'cut', 'paste'
  ];

  function attachEventBlockers() {
    INTERCEPTION_EVENTS.forEach((evt) => {
      window.addEventListener(evt, blockPageInteraction, { capture: true, passive: false });
      document.addEventListener(evt, blockPageInteraction, { capture: true, passive: false });
    });
  }

  function detachEventBlockers() {
    INTERCEPTION_EVENTS.forEach((evt) => {
      window.removeEventListener(evt, blockPageInteraction, { capture: true, passive: false });
      document.removeEventListener(evt, blockPageInteraction, { capture: true, passive: false });
    });
  }

  // ---------------------------------------------------------------------------
  // 3. Tab Title & Favicon Camouflage (Anti-Shoulder-Surfing)
  // ---------------------------------------------------------------------------
  let originalDocumentTitle = '';
  let originalFaviconHref = '';
  let titleObserver = null;
  const DISGUISED_TITLE = 'New Tab';
  const DISGUISED_FAVICON = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6" fill="%238ab4f8"/></svg>';

  function cloakTabIdentity() {
    chrome.storage.local.get(['cpl_settings', 'settings'], (data) => {
      const settings = data.cpl_settings || data.settings;
      if (settings && settings.cloakTabTitle === false) return;

      if (!originalDocumentTitle) {
        originalDocumentTitle = document.title || 'Tab';
      }
      document.title = DISGUISED_TITLE;

      const link = document.querySelector("link[rel*='icon']");
      if (link) {
        if (!originalFaviconHref) originalFaviconHref = link.getAttribute('href') || '';
        link.setAttribute('href', DISGUISED_FAVICON);
      }

      if (!titleObserver) {
        const titleEl = document.querySelector('title');
        if (titleEl) {
          titleObserver = new MutationObserver(() => {
            if (isCurrentlyLocked && document.title !== DISGUISED_TITLE) {
              document.title = DISGUISED_TITLE;
            }
          });
          titleObserver.observe(titleEl, { childList: true, subtree: true, characterData: true });
        }
      }
    });
  }

  function restoreTabIdentity() {
    if (titleObserver) {
      titleObserver.disconnect();
      titleObserver = null;
    }
    if (originalDocumentTitle) {
      document.title = originalDocumentTitle;
      originalDocumentTitle = '';
    }
    if (originalFaviconHref) {
      const link = document.querySelector("link[rel*='icon']");
      if (link) {
        link.setAttribute('href', originalFaviconHref);
      }
      originalFaviconHref = '';
    }
  }

  // ---------------------------------------------------------------------------
  // 4. Overlay Creation & Removal
  // ---------------------------------------------------------------------------

  function injectLockOverlay() {
    if (document.getElementById(OVERLAY_ID)) {
      return; // Already present
    }

    isCurrentlyLocked = true;

    // 1. Camouflage tab title and favicon
    cloakTabIdentity();

    // 2. Prevent underlying page scroll and selection
    if (document.documentElement) {
      document.documentElement.classList.add('cpl-page-locked');
    }
    if (document.body) {
      document.body.classList.add('cpl-page-locked');
    }

    // 3. Create the full-screen opaque overlay container (z-index: 2147483647)
    const overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Profile Lock Screen');

    // 4. Create isolated iframe pointing to lock.html
    const iframe = document.createElement('iframe');
    iframe.id = 'cpl-lock-iframe';
    iframe.src = chrome.runtime.getURL('lock.html?inOverlay=true');
    iframe.allow = 'clipboard-read; clipboard-write';

    overlay.appendChild(iframe);

    // 5. Inject overlay as early as possible
    const targetParent = document.documentElement || document.body;
    if (targetParent) {
      targetParent.appendChild(overlay);
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        if (!document.getElementById(OVERLAY_ID) && isCurrentlyLocked) {
          (document.documentElement || document.body).appendChild(overlay);
        }
      }, { once: true });
    }

    // 6. Attach interaction blockers
    attachEventBlockers();

    // 7. Anti-tampering: Monitor DOM to prevent webpage scripts from removing or hiding overlay
    startOverlayObserver();
  }

  let overlayObserver = null;

  function startOverlayObserver() {
    if (overlayObserver) return;
    const target = document.documentElement || document.body;
    if (!target) return;

    overlayObserver = new MutationObserver(() => {
      if (!isCurrentlyLocked) return;
      const overlay = document.getElementById(OVERLAY_ID);
      if (!overlay || !document.contains(overlay)) {
        injectLockOverlay();
      } else if (overlay.style.display === 'none' || overlay.style.visibility === 'hidden' || overlay.style.opacity === '0') {
        overlay.style.setProperty('display', 'block', 'important');
        overlay.style.setProperty('visibility', 'visible', 'important');
        overlay.style.setProperty('opacity', '1', 'important');
      }
    });

    overlayObserver.observe(target, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['style', 'class', 'hidden']
    });
  }

  function stopOverlayObserver() {
    if (overlayObserver) {
      overlayObserver.disconnect();
      overlayObserver = null;
    }
  }

  function removeLockOverlay() {
    isCurrentlyLocked = false;

    // 0. Stop anti-tampering observer
    stopOverlayObserver();

    // 1. Remove overlay element
    const overlay = document.getElementById(OVERLAY_ID);
    if (overlay && overlay.parentNode) {
      overlay.parentNode.removeChild(overlay);
    }

    // 2. Restore host page scrolling and selection
    if (document.documentElement) {
      document.documentElement.classList.remove('cpl-page-locked');
    }
    if (document.body) {
      document.body.classList.remove('cpl-page-locked');
    }

    // 3. Detach interaction blockers
    detachEventBlockers();

    // 4. Restore original tab title and favicon
    restoreTabIdentity();
  }

  // ---------------------------------------------------------------------------
  // 4. Inactivity Warning Toast
  // ---------------------------------------------------------------------------
  const TOAST_ID = 'cpl-inactivity-toast';
  let toastDismissTimeout = null;

  function showInactivityToast(seconds) {
    if (isCurrentlyLocked) return;
    dismissInactivityToast();

    const toast = document.createElement('div');
    toast.id = TOAST_ID;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');

    const icon = document.createElement('span');
    icon.className = 'cpl-toast-icon';
    icon.textContent = '⏳';

    const text = document.createElement('span');
    text.textContent = `Profile locking in ${seconds || 15}s due to inactivity. Move mouse to stay active.`;

    toast.appendChild(icon);
    toast.appendChild(text);

    const parent = document.body || document.documentElement;
    if (parent) parent.appendChild(toast);

    toastDismissTimeout = setTimeout(dismissInactivityToast, 15000);
  }

  function dismissInactivityToast() {
    const existing = document.getElementById(TOAST_ID);
    if (existing && existing.parentNode) {
      existing.parentNode.removeChild(existing);
    }
    if (toastDismissTimeout) {
      clearTimeout(toastDismissTimeout);
      toastDismissTimeout = null;
    }
  }

  // ---------------------------------------------------------------------------
  // 5. Throttled Activity Tracking (For Idle Auto-Lock)
  // ---------------------------------------------------------------------------
  let lastReportedActivity = 0;
  const ACTIVITY_THROTTLE_MS = 25000; // Notify background at most once every 25 seconds

  /**
   * Captures mouse, keyboard, touch, and scroll interactions.
   * Throttled to avoid CPU overhead and never writes to chrome.storage directly.
   */
  function trackUserActivity() {
    dismissInactivityToast();

    // Only register activity when browsing normally (unlocked)
    if (isCurrentlyLocked) return;

    const now = Date.now();
    if (now - lastReportedActivity < ACTIVITY_THROTTLE_MS) {
      return; // Throttled
    }

    lastReportedActivity = now;

    // Notify service worker that user is active
    try {
      chrome.runtime.sendMessage({ type: 'USER_ACTIVITY' }, () => {
        if (chrome.runtime.lastError) {
          // Suppress benign error if service worker is inactive
        }
      });
    } catch {
      // Ignore
    }
  }

  // Passive event listeners ensure zero impact on scrolling or frame rate
  const ACTIVITY_LISTENERS = [
    'mousemove',
    'mousedown',
    'click',
    'keydown',
    'wheel',
    'scroll',
    'touchstart',
    'pointerdown'
  ];

  ACTIVITY_LISTENERS.forEach((eventName) => {
    window.addEventListener(eventName, trackUserActivity, { passive: true, capture: true });
  });

  // ---------------------------------------------------------------------------
  // 5. Lock State Checking & Synchronization
  // ---------------------------------------------------------------------------

  async function evaluateLockState() {
    try {
      chrome.runtime.sendMessage({ type: 'CHECK_LOCK_STATE' }, (response) => {
        if (chrome.runtime.lastError) {
          checkStorageDirectly();
          return;
        }

        if (response && response.isConfigured && response.isLocked) {
          injectLockOverlay();
        } else {
          removeLockOverlay();
        }
      });
    } catch (err) {
      checkStorageDirectly();
    }
  }

  async function checkStorageDirectly() {
    try {
      if (chrome.storage && chrome.storage.session) {
        const sessionData = await chrome.storage.session.get(['isLocked', 'cpl_session_locked']);
        const isLocked = sessionData.isLocked !== false && sessionData.cpl_session_locked !== false;

        const localData = await chrome.storage.local.get(['setupComplete', 'passwordHash']);
        const isConfigured = Boolean(localData.setupComplete && localData.passwordHash);

        if (isConfigured && isLocked) {
          injectLockOverlay();
        } else {
          removeLockOverlay();
        }
      }
    } catch {
      // Storage session not directly accessible; background message will resolve
    }
  }

  // ---------------------------------------------------------------------------
  // 6. Message & Storage Listeners
  // ---------------------------------------------------------------------------

  // Listener for unlock/lock and warning broadcast from background.js
  chrome.runtime.onMessage.addListener((message) => {
    if (message && message.type === 'LOCK_STATE_CHANGED') {
      dismissInactivityToast();
      if (message.isLocked) {
        injectLockOverlay();
      } else {
        removeLockOverlay();
      }
    } else if (message && message.type === 'SHOW_INACTIVITY_WARNING') {
      showInactivityToast(message.secondsRemaining || 15);
    }
  });

  // Listener for postMessage from embedded lock iframe
  // Strictly verify that the sender origin matches this extension's runtime URL
  window.addEventListener('message', (event) => {
    const extensionOrigin = chrome.runtime.getURL('').replace(/\/$/, '');
    if (event.origin === extensionOrigin && event.data && event.data.type === 'CPL_UNLOCKED') {
      removeLockOverlay();
    }
  });

  // Listener for storage changes
  if (chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === 'session') {
        if (changes.isLocked !== undefined) {
          if (changes.isLocked.newValue === false) {
            removeLockOverlay();
          } else if (changes.isLocked.newValue === true) {
            injectLockOverlay();
          }
        }
      }
    });
  }

  // Run evaluation immediately at document_start
  evaluateLockState();

})();
