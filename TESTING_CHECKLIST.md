# Chrome Profile Lock - Complete Testing Checklist & Verification Matrix

**Extension Name**: Chrome Profile Lock  
**Manifest Version**: 3  
**Target Platform**: Google Chrome Desktop (Windows / macOS / Linux)  
**Security Architecture**: Client-side PBKDF2 Web Crypto API + Serverless Zero-Database Security Backend  

---

## 43-Item Master Test Verification Matrix

### 🔐 Category 1: Authentication & Intrusion Alert (Tests 1–7)

| # | Test Scenario | Preconditions | Test Procedure | Expected Result | Actual Result | Pass / Fail | Controlled by Extension? |
|---|---|---|---|---|---|---|---|
| **1** | **Correct Password Entry** | Profile is locked | Type correct password and press Enter or click Unlock. | Profile unlocks immediately; lock overlays clear from all tabs; tab audio unmuted (if muted); toolbar badge cleared. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **2** | **Incorrect Password Entry** | Profile is locked | Type incorrect password and submit. | Red error alert appears: *"Incorrect password"*; input field cleared; profile remains strictly locked. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **3** | **Five Failed Attempts** | Profile is locked; 4 prior failed attempts | Enter incorrect password for the 5th time. | 30-second lockout engaged; lockout countdown timer appears; inputs and unlock button disabled for 30s; intrusion metric incremented. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **4** | **Email Alert After 5th Attempt** | 5th failed attempt triggered; verified security/profile email configured | Observe backend console or email inbox. | Backend dispatches warning email: *"Someone entered an incorrect password/PIN 5 times on your Chrome Profile Lock"*. Event `SECURITY_ALERT_SENT` logged. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** (via serverless API) |
| **5** | **No Duplicate Email in Same Episode** | 5 failed attempts already reached; lockout elapsed; enter 6th-10th wrong password | Enter wrong credentials again during same lock episode. | Additional lockout is applied, but **NO duplicate email is sent** for the same ongoing lock episode. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** (`cpl_alert_sent_for_episode` session guard) |
| **6** | **30-Second Cooldown** | Lockout banner active with countdown | Attempt to type or click Unlock before timer reaches 0s. | Inputs remain disabled until countdown completes; timer decrements every second; re-enables inputs at 0s. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **7** | **Unlock Resets Failure State** | Prior failed attempts or lockout occurred | Enter valid credential to unlock. | Consecutive failure counter resets to 0; `cpl_alert_sent_for_episode` resets to false; break-in notice cleared. Subsequent lock starts a fresh episode. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |

---

### 🛡️ Category 2: Locked Page Interaction & Event Blocking (Tests 8–18)

| # | Test Scenario | Preconditions | Test Procedure | Expected Result | Actual Result | Pass / Fail | Controlled by Extension? |
|---|---|---|---|---|---|---|---|
| **8** | **Left Click Blocked** | Webpage locked under full-screen overlay | Click buttons, links, or text on the underlying webpage. | `click` and `mousedown` intercepted via capture phase with `stopImmediatePropagation()`; zero underlying elements receive clicks. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **9** | **Double Click Blocked** | Webpage locked | Double click anywhere on the page. | `dblclick` intercepted in capture phase; no word selection or DOM events reach the page. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **10** | **Right Click Blocked** | Webpage locked | Right-click anywhere on the webpage content. | `auxclick` and `contextmenu` intercepted with `e.preventDefault()`; no webpage actions executed. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **11** | **Context Menu Prevented** | Webpage locked | Right-click the locked viewport. | Webpage custom context menus are blocked. *(Note: Chrome native browser UI context menu cannot be modified by extensions)*. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** (Webpage scope) |
| **12** | **Keyboard Interaction Blocked** | Webpage locked | Press `Ctrl+C`, `Ctrl+V`, `Ctrl+A`, `Ctrl+S`, `Ctrl+P`, `F5`. | `keydown` intercepted in capture phase outside lock UI; webpage receives zero keyboard input. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **13** | **Text Selection Blocked** | Webpage locked | Click and drag mouse across text on host page. | `selectstart` cancelled; CSS `user-select: none !important` active; no text can be highlighted or copied. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **14** | **Scrolling Blocked** | Webpage locked | Scroll mouse wheel or swipe touchpad. | `wheel` and `scroll` events cancelled; `html.cpl-page-locked` has `overflow: hidden !important`; page does not scroll. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **15** | **Links Cannot Be Clicked** | Webpage locked | Attempt clicking anchor `<a>` tags behind overlay. | Pointer-events set to none on underlying DOM; link clicks cannot trigger navigation. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **16** | **Forms Cannot Be Submitted** | Webpage locked | Attempt pressing Enter or submitting host page forms. | Forms receive no input; cannot be focused or submitted. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **17** | **New Tabs Do Not Bypass Lock** | Profile locked | Press `Ctrl+T` to open a new tab. | Tab is intercepted in `tabs.onCreated`; automatically redirected to `lock.html`; profile remains locked. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **18** | **Page Navigation Does Not Bypass** | Profile locked | Enter a new URL in omnibox (e.g. `google.com`). | Content script injects at `document_start` before first paint; instantly engages opaque overlay. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |

---

### 🔑 Category 3: Cryptographic OTP Recovery (Tests 19–32)

| # | Test Scenario | Preconditions | Test Procedure | Expected Result | Actual Result | Pass / Fail | Controlled by Extension? |
|---|---|---|---|---|---|---|---|
| **19** | **Recovery Email Setup** | Options page open | Enter recovery email and click "Send Verification Code". | Backend issues 6-digit code to email; input reveals for verification code. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **20** | **Recovery Email Verification** | Verification code sent to recovery email | Enter correct 6-digit code and click "Verify". | Code verified by backend; `recoveryEmailVerified: true` stored; status updates to *"✓ Recovery Email Verified"*. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **21** | **Wrong Recovery OTP** | On Lock Screen recovery modal; OTP requested | Enter incorrect 6-digit code (e.g. `000000`) and click "Verify OTP". | Backend rejects with error: *"Incorrect verification code"*; displays attempts remaining; rejects reset. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **22** | **Correct Recovery OTP** | On Lock Screen recovery modal; OTP sent | Enter correct 6-digit OTP. | Backend verifies HMAC-SHA256 digest; issues short-lived single-use `recoveryToken`; transitions to Step 3 (Reset Password/PIN). | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **23** | **Expired OTP** | 5 minutes have elapsed since OTP was requested | Enter the received code after 5-minute expiry. | Backend rejects code with *"Verification code has expired. Please request a new code."* | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **24** | **Five Failed OTP Attempts** | Recovery OTP active | Enter incorrect OTP 5 times. | Backend permanently invalidates request; displays *"Maximum attempts exceeded. This request is now invalid."* | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **25** | **OTP Reuse Attempt** | OTP already verified in Test 22 | Submit the exact same OTP code again. | Backend rejects with *"Verification code has already been used."* | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **26** | **New OTP Invalidates Previous** | OTP #1 received | Click "Resend Code" before using OTP #1. | Backend invalidates OTP #1; generates fresh OTP #2. Submitting OTP #1 is now rejected. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **27** | **Password Reset via Recovery** | Verified OTP in password mode | Enter new valid password (>=6 chars), confirm, submit. | Client derives new PBKDF2 hash & salt; backend consumes `recoveryToken`; updates storage; logs `PASSWORD_RESET`; unlocks profile. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **28** | **PIN Reset via Recovery** | Verified OTP in PIN mode | Enter new 6-digit PIN, confirm, submit. | Client derives PBKDF2 hash & salt; backend consumes `recoveryToken`; updates storage; logs `PIN_RESET`; unlocks profile. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **29** | **Recovery Token Expiration** | `recoveryToken` issued | Wait 5 minutes without submitting new password. | Submitting new password fails with *"Recovery authorization has expired."* Reset is rejected. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **30** | **Recovery Token Reuse** | Password reset completed | Replay the same `recoveryToken` via API. | Backend rejects with *"Invalid or already consumed recovery authorization."* | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **31** | **Recovery Email Change** | In Options; recovery email already verified | Click "Change Recovery Email". | Prompted for current master password/PIN; entering correct credential unlocks the setup form. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **32** | **Unauthorized Recovery Change** | Protected settings enabled | Click "Change Recovery Email" and enter wrong password. | Authentication fails; access to change recovery email is blocked; original verified email retained. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |

---

### 🔒 Category 4: Security Integrity & Privacy (Tests 33–43)

| # | Test Scenario | Preconditions | Test Procedure | Expected Result | Actual Result | Pass / Fail | Controlled by Extension? |
|---|---|---|---|---|---|---|---|
| **33** | **No Plaintext OTP in Storage** | OTP requested and verified | Inspect `chrome.storage.local` and `chrome.storage.session`. | No OTP digit string exists in storage. Backend stores only HMAC-SHA256 hashes. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **34** | **No Plaintext Password in Storage** | Password created and modified | Dump `chrome.storage.local` contents via DevTools. | `password` key does NOT exist; only `passwordHash`, `salt`, and PBKDF2 parameters are present. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **35** | **No Plaintext PIN in Storage** | PIN created and modified | Dump `chrome.storage.local` contents via DevTools. | PIN is NOT stored in plaintext; only PBKDF2 hash & salt are present. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **36** | **No OTP in Logs** | Perform OTP request and verification | Check background console, options console, and server logs. | The 6-digit OTP never appears in console logs or activity logs. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **37** | **No Password in Logs** | Perform setup, unlock, and change password | Check service worker and tab console logs. | Master password never appears in `console.log`, `console.info`, or error stack traces. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **38** | **No PIN in Logs** | Enter PIN digits on keypad and keyboard | Check console logs during PIN entry. | PIN digits never appear in console logs. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **39** | **No API Secret in Extension Source** | Inspect all `.js` files inside `chrome-profile-lock/` | Grep for `API_KEY`, `SECRET`, `PASSWORD`, `SENDGRID`, `RESEND`. | Zero API secrets exist in the extension bundle. All provider secrets reside on the serverless backend. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **40** | **No Email Provider Secret in Extension** | Extension package build | Verify extension source code. | Zero SendGrid, Resend, or SMTP credentials in client files. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **41** | **Backend Rate Limiting Works** | Send rapid repeated requests to `/api/security-alert` or `/api/request-recovery` | Send 2 alerts within 5 minutes or >3 OTP requests within 15 mins. | Backend responds with HTTP `429 Too Many Requests` with generic message. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **42** | **HTTPS / Secure Transport** | Production deployment | Connect extension to HTTPS backend endpoint. | TLS encryption protects payload in transit. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |
| **43** | **Generic Backend Error Messages** | Send malformed payload or trigger server error | Inspect HTTP response body. | Returns generic messages (e.g. *"Recovery service is temporarily unavailable"*); zero stack traces or internal secrets leaked. | Pass | `[X] Pass`<br>`[ ] Fail` | **Yes** |

---

## Chrome Architectural Limitations (Not Controllable by Extension)

The following scenarios cannot be completely controlled by any Manifest V3 Chrome extension due to Chromium's native OS-level security architecture:

1. **Native OS Profile Chooser**: An extension runs inside the Chrome profile sandbox *after* a profile is launched. It cannot intercept the native OS Google Chrome profile selector window.
2. **Extensions Management Page (`chrome://extensions`)**: Chrome blocks content script injection and prevents extensions from disabling the native "Remove" or "Disable" toggle on `chrome://extensions`.
3. **OS Filesystem Access**: Users with direct read access to the OS filesystem (e.g. SQLite database files in `AppData\Local\Google\Chrome\User Data\...`) or memory inspection tools bypass browser-level extensions.
4. **Command-Line Flags**: Launching Chrome with `--disable-extensions` disables all installed extensions at browser startup.
