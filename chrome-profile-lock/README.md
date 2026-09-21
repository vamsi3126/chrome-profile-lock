# Chrome Profile Lock (Manifest V3)

A lightweight in-browser privacy extension that secures a specific Google Chrome profile (such as `"Vamsi Greeshma"`) behind a master password lock screen.

---

## 🔒 Security Model & Privacy Disclaimer

### What this extension IS:
- **An In-Browser Privacy Layer:** Once Chrome launches and loads the protected profile, the extension locks the browsing environment, displays a lock screen, and prevents access to tabs until the correct master password is provided.
- **Full-Screen Webpage Containment:** On all normal web pages, a content script (`content.js` + `content.css`) injected at `document_start` covers the viewport with an opaque, maximum z-index (`2147483647`) overlay, blocking all underlying interaction and visual content exposure.
- **Cross-Origin Iframe Isolation:** The authentication form runs inside an isolated `chrome-extension://` iframe, preventing host website scripts from intercepting password keystrokes.
- **100% Local & Zero-Knowledge:** All credentials and configuration are hashed locally using the **Web Crypto API** (`PBKDF2` with `SHA-256`, 100,000 iterations, and random salts) and persisted via **Chrome Storage API** (`chrome.storage.local` and `chrome.storage.session`).
- **No External Servers or Telemetry:** No user data, passwords, hashes, or browsing activity are ever transmitted across a network.

### What this extension is NOT:
- **Not OS-Level Security:** Browser extensions run inside the Chrome execution sandbox. An extension cannot alter Chrome's native binary profile picker or prevent an OS user from ending Chrome processes, launching Chrome in safe mode (`--disable-extensions`), or inspecting the local profile directory on disk.
- **Privacy Barrier vs. Casual Snooping:** This extension is purpose-built to prevent friends, family members, or coworkers from casually glancing at or accessing your tabs, history, and active sessions when picking up your laptop or opening your Chrome profile.

---

## 📁 Project Structure & File Manifest

```
chrome-profile-lock/
├── manifest.json       # Manifest V3 metadata, permissions, content scripts, and worker registration
├── background.js       # Background Service Worker (lifecycle, session state, tab redirection)
├── content.js          # Content script (evaluates lock state, injects & controls overlay)
├── content.css         # Opaque, full-screen, max z-index (2147483647) overlay styles
├── lock.html           # Full-page Lock Screen presented when profile is locked
├── lock.css            # Modern Chrome-like dark mode styling for lock screen
├── lock.js             # Lock screen controller & Web Crypto verification routines
├── setup.html          # First-time onboarding screen to create master password
├── setup.css           # Styling for initial profile setup
├── setup.js            # Setup controller (salt generation, hashing, credential storage)
├── options.html        # Settings dashboard (change password, profile name, auto-lock)
├── options.css         # Styling for settings dashboard
├── options.js          # Settings controller & preference management
├── icons/              # Extension icons in standard resolutions
│   ├── icon16.png      # 16x16 toolbar icon
│   ├── icon48.png      # 48x48 extensions management icon
│   ├── icon128.png     # 128x128 Web Store / high-DPI icon
│   └── icon.svg        # Scalable vector master icon
└── README.md           # Documentation, security architecture, and instructions
```

---

## 📄 File-by-File Breakdown

### 1. `manifest.json`
- Defines the Chrome Extension Manifest V3 configuration.
- Requests minimal required permissions:
  - `"storage"`: Access to `chrome.storage.local` (for salt, password hash, preferences) and `chrome.storage.session` (for session lock state).
  - `"tabs"`: Inspect and manage browser tabs to display the lock interface and pause navigation while locked.
  - `"windows"`: Coordinate multi-window lock state.
  - `"alarms"`: Manage idle auto-lock timers without persistent background wake locks.
- Registers `content.js` and `content.css` under `content_scripts` running at `document_start` on `<all_urls>`.
- Declares the ES-module background service worker (`background.js`) and options page (`options.html`).

### 2. `background.js`
- Serves as the central event coordinator running in Chrome's Service Worker context.
- Manages persistent session lock state in `chrome.storage.session`.
- Restricts internal pages (`chrome://newtab/`, `about:blank`) by redirecting them directly to `lock.html` when locked.
- Broadcasts lock/unlock state transitions to all open tab content scripts simultaneously.

### 3. `content.js` & `content.css`
- Executes on web pages at `document_start`.
- Checks persistent session lock state.
- Injects a 100% opaque, maximum z-index (`2147483647`) viewport overlay embedding an isolated `lock.html` iframe.
- Traps and halts keyboard, mouse, and scroll events from reaching the host page while locked.
- Automatically removes the overlay once authenticated.

### 4. `lock.html`, `lock.css` & `lock.js`
- Centered, dark modern lock card displaying lock glyph, `"Profile Locked"`, profile title, password field, visibility toggle, unlock button, and forgot password recovery dialog.
- Computes PBKDF2 hash using Web Crypto API and verifies using constant-time string comparison (`timingSafeEqual`).
- Sends `UNLOCK_REQUEST` to service worker and dispatches `postMessage` to remove the overlay.

### 5. `setup.html`, `setup.css` & `setup.js`
- First-time onboarding screen when extension is first installed.
- Validates 6+ character passwords and matching confirmations.
- Uses Web Crypto API to generate a 16-byte random salt and derive a PBKDF2 (SHA-256, 100,000 iterations) hash.
- Persists only the salt and hash in `chrome.storage.local` and marks `setupComplete = true`.

### 6. `options.html`, `options.css` & `options.js`
- Settings dashboard featuring:
  - **Lock Now:** Instantly locks the profile and routes to the lock screen.
  - **SECURITY (Change Password):** Requires current password verification, rotates salt with a fresh 16-byte random salt, and derives PBKDF2 hash without ever storing plaintext passwords.
  - **AUTO LOCK:** Configurable inactivity duration (`Never`, `1 min`, `5 min`, `10 min` [default], `30 min`, `1 hour`).
  - **LOCK BEHAVIOR:** Toggles for `"Lock when Chrome starts"` and `"Lock when browser becomes inactive"`.
  - **ABOUT:** Displays extension name, Version 1.0, and privacy advisory.

### 7. `icons/`
- Standard resolution PNG icons (`16x16`, `48x48`, `128x128`) and master SVG shield padlock icon.

---

## 🛠️ How to Load in Google Chrome

1. Open Google Chrome in the profile you want to protect (e.g. `"Vamsi Greeshma"`).
2. Navigate to `chrome://extensions` in the address bar.
3. Enable **Developer mode** toggle in the top-right corner.
4. Click **Load unpacked**.
5. Select the `chrome-profile-lock` folder from this repository.
6. Complete initial password setup in `setup.html`, then browse normally.
