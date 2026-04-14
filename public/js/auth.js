'use strict';

let sessionId = null;
let countdownInterval = null;
let totalExpiry = 250;

// ─── Helpers ────────────────────────────────────────────────────────────────

function getCookie(name) {
  const val = document.cookie.split('; ').find(r => r.startsWith(name + '='));
  return val ? decodeURIComponent(val.split('=')[1]) : null;
}

async function getCsrfToken() {
  // Always fetch fresh from server to ensure cookie is set
  const res = await fetch('/auth/csrf-token', { credentials: 'include' });
  const data = await res.json();
  return data.csrfToken;
}

function showError(elId, textId, message) {
  const wrap = document.getElementById(elId);
  document.getElementById(textId).textContent = message;
  wrap.classList.remove('hidden');
}

function hideError(elId) {
  document.getElementById(elId).classList.add('hidden');
}

function setEmailLoading(loading) {
  const btn = document.getElementById('btn-request');
  btn.disabled = loading;
  document.getElementById('btn-spinner').classList.toggle('hidden', !loading);
  document.getElementById('btn-text').textContent = loading ? 'Sending...' : 'Send login link';
}

function setVerifyLoading(loading) {
  const btn = document.getElementById('btn-verify');
  btn.disabled = loading;
  document.getElementById('verify-spinner').classList.toggle('hidden', !loading);
  document.getElementById('verify-text').textContent = loading ? 'Verifying...' : 'Verify code';
}

// ─── Email validation ───────────────────────────────────────────────────────

function isValidEmail(email) {
  // Accept any standard email including gmail.com, yahoo.com, custom domains etc.
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim());
}

// ─── Request login ──────────────────────────────────────────────────────────

async function requestLogin() {
  const emailInput = document.getElementById('email');
  const email = emailInput.value.trim();

  hideError('error-msg');

  if (!email) {
    showError('error-msg', 'error-msg-text', 'Please enter your email address.');
    emailInput.focus();
    return;
  }

  if (!isValidEmail(email)) {
    showError('error-msg', 'error-msg-text', 'Please enter a valid email address (e.g. yourname@gmail.com).');
    emailInput.focus();
    return;
  }

  setEmailLoading(true);

  try {
    const csrfToken = await getCsrfToken();

    const res = await fetch('/auth/request', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken,
      },
      body: JSON.stringify({ email }),
    });

    const data = await res.json();

    if (!res.ok) {
      showError('error-msg', 'error-msg-text', data.error || 'Failed to send login email. Please try again.');
      return;
    }

    sessionId = data.sessionId;
    totalExpiry = data.expiresIn || 250;

    // Show OTP step
    document.getElementById('sent-email').textContent = email;
    document.getElementById('step-email').classList.add('hidden');
    const otpStep = document.getElementById('step-otp');
    otpStep.classList.remove('hidden');
    otpStep.classList.add('step-enter');

    // Start timers
    startCountdown(totalExpiry);
    startProgressBar(totalExpiry);

    focusFirstOtpBox();
  } catch (err) {
    showError('error-msg', 'error-msg-text', 'Network error. Check your connection and try again.');
  } finally {
    setEmailLoading(false);
  }
}

// ─── Progress bar (top of page) ─────────────────────────────────────────────

function startProgressBar(seconds) {
  const wrap = document.getElementById('progress-bar-wrap');
  const fill = document.getElementById('progress-bar-fill');
  wrap.style.display = 'block';
  fill.style.width = '100%';

  let elapsed = 0;
  const step = 1000;
  const interval = setInterval(() => {
    elapsed++;
    const pct = Math.max(0, ((seconds - elapsed) / seconds) * 100);
    fill.style.width = pct + '%';
    if (elapsed >= seconds) {
      clearInterval(interval);
      fill.style.width = '0%';
    }
  }, step);
}

// ─── Countdown ring ──────────────────────────────────────────────────────────

function startCountdown(seconds) {
  if (countdownInterval) clearInterval(countdownInterval);

  const numEl = document.getElementById('countdown-number');
  const ringEl = document.getElementById('ring-circle');
  const labelEl = document.getElementById('countdown-label');
  const resendRow = document.getElementById('resend-row');

  const circumference = 188.5; // 2 * π * 30
  let remaining = seconds;

  function update() {
    numEl.textContent = remaining;
    const offset = circumference * (1 - remaining / seconds);
    ringEl.setAttribute('stroke-dashoffset', offset);

    // Color ring red when under 30s
    if (remaining <= 30) {
      ringEl.classList.add('expired');
    }
  }

  update();

  countdownInterval = setInterval(() => {
    remaining--;
    update();
    if (remaining <= 0) {
      clearInterval(countdownInterval);
      numEl.textContent = '0';
      labelEl.textContent = 'Expired — request a new link';
      ringEl.classList.add('expired');
      resendRow.classList.remove('hidden');
      document.getElementById('btn-verify').disabled = true;
    }
  }, 1000);
}

// ─── OTP box interactions ────────────────────────────────────────────────────

function focusFirstOtpBox() {
  const boxes = document.querySelectorAll('.otp-box');
  if (boxes.length) boxes[0].focus();
}

function getOtpValue() {
  return [...document.querySelectorAll('.otp-box')].map(b => b.value).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  const boxes = [...document.querySelectorAll('.otp-box')];

  boxes.forEach((box, index) => {
    box.addEventListener('input', e => {
      const val = e.target.value.replace(/\D/g, '');
      e.target.value = val ? val[val.length - 1] : '';
      e.target.classList.toggle('filled', !!e.target.value);
      if (val && index < boxes.length - 1) {
        boxes[index + 1].focus();
      }
      // Auto-verify when all filled
      const full = getOtpValue();
      if (full.length === 8) verifyOtp();
    });

    box.addEventListener('keydown', e => {
      if (e.key === 'Backspace') {
        if (!e.target.value && index > 0) {
          boxes[index - 1].value = '';
          boxes[index - 1].classList.remove('filled');
          boxes[index - 1].focus();
        }
        e.target.classList.remove('filled');
      }
      if (e.key === 'Enter') verifyOtp();
      if (e.key === 'ArrowLeft'  && index > 0)              boxes[index - 1].focus();
      if (e.key === 'ArrowRight' && index < boxes.length-1) boxes[index + 1].focus();
    });

    box.addEventListener('paste', e => {
      e.preventDefault();
      const pasted = (e.clipboardData || window.clipboardData)
        .getData('text').replace(/\D/g, '').slice(0, 8);
      [...pasted].forEach((char, i) => {
        if (boxes[i]) {
          boxes[i].value = char;
          boxes[i].classList.add('filled');
        }
      });
      const next = Math.min(pasted.length, boxes.length - 1);
      boxes[next].focus();
      if (pasted.length === 8) verifyOtp();
    });
  });

  // Enter on email field
  const emailInput = document.getElementById('email');
  if (emailInput) emailInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') requestLogin();
  });
});

// ─── Verify OTP ──────────────────────────────────────────────────────────────

async function verifyOtp() {
  const otp = getOtpValue();
  hideError('otp-error');

  if (otp.length !== 8 || !/^\d{8}$/.test(otp)) {
    showError('otp-error', 'otp-error-text', 'Please enter all 8 digits of your code.');
    return;
  }

  if (!sessionId) {
    showError('otp-error', 'otp-error-text', 'Session lost. Please request a new login link.');
    return;
  }

  setVerifyLoading(true);

  try {
    const csrfToken = await getCsrfToken();

    const res = await fetch('/auth/verify-otp', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken,
      },
      body: JSON.stringify({ sessionId, otp }),
    });

    const data = await res.json();

    if (!res.ok) {
      showError('otp-error', 'otp-error-text', data.error || 'Verification failed.');
      // Clear boxes and refocus
      document.querySelectorAll('.otp-box').forEach(b => {
        b.value = '';
        b.classList.remove('filled');
      });
      focusFirstOtpBox();
      return;
    }

    // Success — stop timers and redirect
    if (countdownInterval) clearInterval(countdownInterval);
    document.getElementById('progress-bar-wrap').style.display = 'none';
    window.location.href = '/dashboard';
  } catch (err) {
    showError('otp-error', 'otp-error-text', 'Network error. Check your connection and try again.');
  } finally {
    setVerifyLoading(false);
  }
}

// ─── Reset ───────────────────────────────────────────────────────────────────

function resetToEmail() {
  if (countdownInterval) clearInterval(countdownInterval);
  document.getElementById('progress-bar-wrap').style.display = 'none';
  sessionId = null;

  document.getElementById('step-otp').classList.add('hidden');
  document.getElementById('step-email').classList.remove('hidden');
  document.querySelectorAll('.otp-box').forEach(b => {
    b.value = '';
    b.classList.remove('filled');
  });
  hideError('otp-error');
  hideError('error-msg');
  document.getElementById('resend-row').classList.add('hidden');
  document.getElementById('btn-verify').disabled = false;
  document.getElementById('email').focus();
}
