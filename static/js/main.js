/**
 * main.js - SecureAuth Lab Client-Side Logic
 * Pure vanilla JavaScript (No external libraries)
 *
 * Implements:
 *   1. Accessible password visibility toggles.
 *   2. Real-time client-side password strength meter & criteria checklist.
 *   3. Non-blocking form submission states with spinner.
 *   4. Live server-synchronized session inactivity timer & warning modal.
 *   5. Session heartbeat refresh via secure AJAX endpoint.
 */

(function () {
    'use strict';

    // Global namespace for SecureAuth helpers
    window.SecureAuth = window.SecureAuth || {};

    /* -------------------------------------------------------------------------
       1. Password Visibility Toggle
       ------------------------------------------------------------------------- */
    function initPasswordToggles() {
        const toggleButtons = document.querySelectorAll('.password-toggle-btn');
        toggleButtons.forEach(button => {
            button.addEventListener('click', function () {
                const targetId = this.getAttribute('data-target');
                const passwordInput = document.getElementById(targetId);
                if (!passwordInput) return;

                const isPassword = passwordInput.getAttribute('type') === 'password';
                passwordInput.setAttribute('type', isPassword ? 'text' : 'password');

                // Toggle eye SVG icons
                const eyeIcon = this.querySelector('.eye-icon');
                const eyeOffIcon = this.querySelector('.eye-off-icon');

                if (eyeIcon && eyeOffIcon) {
                    eyeIcon.classList.toggle('hidden', isPassword);
                    eyeOffIcon.classList.toggle('hidden', !isPassword);
                }

                // Update accessible aria-label
                this.setAttribute(
                    'aria-label',
                    isPassword ? 'Hide password' : 'Show password'
                );
            });
        });
    }

    /* -------------------------------------------------------------------------
       2. Real-Time Password Strength Meter & Complexity Checklist
       ------------------------------------------------------------------------- */
    function initPasswordStrengthValidation() {
        const passwordInput = document.getElementById('password');
        const confirmInput = document.getElementById('confirm_password');
        const meterFill = document.getElementById('meterFill');
        const meterStatus = document.getElementById('meterStatus');

        if (!passwordInput) return;

        // Checklist elements
        const chkLength = document.getElementById('chkLength');
        const chkUpper = document.getElementById('chkUpper');
        const chkLower = document.getElementById('chkLower');
        const chkDigit = document.getElementById('chkDigit');
        const chkSpecial = document.getElementById('chkSpecial');
        const chkMatch = document.getElementById('chkMatch');

        function updateItem(el, isValid) {
            if (!el) return;
            const icon = el.querySelector('.check-icon');
            if (isValid) {
                el.classList.add('valid');
                if (icon) icon.textContent = '✓';
            } else {
                el.classList.remove('valid');
                if (icon) icon.textContent = '✕';
            }
        }

        function evaluatePassword() {
            const val = passwordInput.value || '';
            const confirmVal = confirmInput ? (confirmInput.value || '') : '';

            const hasLength = val.length >= 8;
            const hasUpper = /[A-Z]/.test(val);
            const hasLower = /[a-z]/.test(val);
            const hasDigit = /[0-9]/.test(val);
            const hasSpecial = /[!@#$%^&*(),.?":{}|<>\-_=+\\/[\]~`]/.test(val);
            const isMatch = val.length > 0 && val === confirmVal;

            updateItem(chkLength, hasLength);
            updateItem(chkUpper, hasUpper);
            updateItem(chkLower, hasLower);
            updateItem(chkDigit, hasDigit);
            updateItem(chkSpecial, hasSpecial);
            if (confirmInput) updateItem(chkMatch, isMatch);

            // Calculate strength score
            let score = 0;
            if (val.length >= 8) score += 20;
            if (val.length >= 12) score += 10;
            if (hasUpper) score += 20;
            if (hasLower) score += 15;
            if (hasDigit) score += 15;
            if (hasSpecial) score += 20;

            if (score > 100) score = 100;

            if (meterFill && meterStatus) {
                meterFill.style.width = score + '%';

                if (val.length === 0) {
                    meterFill.style.backgroundColor = 'transparent';
                    meterStatus.textContent = 'Enter password';
                    meterStatus.style.color = 'var(--text-muted)';
                } else if (score < 40) {
                    meterFill.style.backgroundColor = '#ef4444'; // Red
                    meterStatus.textContent = 'Weak';
                    meterStatus.style.color = '#f87171';
                } else if (score < 70) {
                    meterFill.style.backgroundColor = '#f59e0b'; // Amber
                    meterStatus.textContent = 'Moderate';
                    meterStatus.style.color = '#fbbf24';
                } else if (score < 90) {
                    meterFill.style.backgroundColor = '#3b82f6'; // Blue
                    meterStatus.textContent = 'Strong';
                    meterStatus.style.color = '#60a5fa';
                } else {
                    meterFill.style.backgroundColor = '#10b981'; // Emerald
                    meterStatus.textContent = 'Very Strong (Cyber-Ready)';
                    meterStatus.style.color = '#34d399';
                }
            }
        }

        passwordInput.addEventListener('input', evaluatePassword);
        if (confirmInput) {
            confirmInput.addEventListener('input', evaluatePassword);
        }
    }

    /* -------------------------------------------------------------------------
       3. Form Submission UX with Spinner State
       ------------------------------------------------------------------------- */
    function initFormSubmitStates() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', function () {
                const submitBtn = this.querySelector('button[type="submit"]');
                if (!submitBtn) return;

                const spinner = submitBtn.querySelector('.spinner');
                const btnText = submitBtn.querySelector('.btn-text');

                // Don't disable immediately to allow form values to serialize cleanly
                setTimeout(() => {
                    submitBtn.disabled = true;
                    if (spinner) spinner.classList.remove('hidden');
                    if (btnText && form.id === 'loginForm') {
                        btnText.textContent = 'Authenticating Credentials...';
                    } else if (btnText && form.id === 'registerForm') {
                        btnText.textContent = 'Computing Argon2id Hash...';
                    }
                }, 10);
            });
        });
    }

    /* -------------------------------------------------------------------------
       4. Live Session Inactivity Countdown & Auto-Termination
       ------------------------------------------------------------------------- */
    window.SecureAuth.initDashboardTimer = function (initialSecondsRemaining, totalTimeoutSeconds) {
        let remaining = initialSecondsRemaining;
        const total = totalTimeoutSeconds || 1200; // 20 minutes default

        const timerDisplay = document.getElementById('sessionTimerDisplay');
        const progressFill = document.getElementById('sessionProgressFill');
        const warningModal = document.getElementById('expiryWarningModal');
        const modalSeconds = document.getElementById('modalSecondsRemaining');
        const extendBtn = document.getElementById('extendSessionBtn');
        const refreshBtn = document.getElementById('refreshSessionBtn');

        function formatTime(seconds) {
            const m = Math.floor(seconds / 60);
            const s = seconds % 60;
            return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
        }

        function updateUI() {
            if (timerDisplay) {
                timerDisplay.textContent = formatTime(remaining);

                if (remaining <= 60) {
                    timerDisplay.classList.add('warning');
                } else {
                    timerDisplay.classList.remove('warning');
                }
            }

            if (progressFill) {
                const percent = Math.max(0, Math.min(100, (remaining / total) * 100));
                progressFill.style.width = percent + '%';
            }

            // Show modal when under 60 seconds
            if (remaining <= 60 && remaining > 0 && warningModal) {
                warningModal.classList.remove('hidden');
                if (modalSeconds) modalSeconds.textContent = remaining;
            }

            // Expiry reached
            if (remaining <= 0) {
                window.location.href = '/login';
            }
        }

        // Tick every 1 second
        const countdownInterval = setInterval(() => {
            remaining--;
            updateUI();
            if (remaining <= 0) {
                clearInterval(countdownInterval);
            }
        }, 1000);

        // Heartbeat heartbeat extension function
        function keepSessionAlive() {
            fetch('/api/session-status', {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(res => res.json())
            .then(data => {
                if (data.authenticated && data.seconds_remaining) {
                    remaining = data.seconds_remaining;
                    if (warningModal) warningModal.classList.add('hidden');
                    updateUI();
                } else {
                    window.location.href = '/login';
                }
            })
            .catch(() => {
                // In case of network glitch, reload
                window.location.reload();
            });
        }

        if (extendBtn) {
            extendBtn.addEventListener('click', keepSessionAlive);
        }

        if (refreshBtn) {
            refreshBtn.addEventListener('click', keepSessionAlive);
        }

        // Initialize display immediately
        updateUI();
    };

    /* -------------------------------------------------------------------------
       DOM Ready Initialization
       ------------------------------------------------------------------------- */
    document.addEventListener('DOMContentLoaded', () => {
        initPasswordToggles();
        initPasswordStrengthValidation();
        initFormSubmitStates();
    });

})();
