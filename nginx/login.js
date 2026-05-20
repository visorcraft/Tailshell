(function () {
  const form = document.getElementById('loginForm');
  const errorDiv = document.getElementById('error');
  const submitBtn = document.getElementById('submitBtn');
  const mfaGroup = document.getElementById('mfa-group');
  const totpInput = document.getElementById('totp');
  const captchaGroup = document.getElementById('captcha-group');
  const turnstileContainer = document.getElementById('turnstile-container');

  let turnstileSiteKey = '';
  let turnstileWidgetId = null;
  let captchaRequired = false;
  let turnstileScriptLoading = false;

  function showError(message) {
    errorDiv.textContent = message;
    errorDiv.classList.add('visible');
  }

  function hideError() {
    errorDiv.classList.remove('visible');
    errorDiv.textContent = '';
  }

  function showMfa() {
    if (!mfaGroup) return;
    mfaGroup.classList.remove('hidden');
    if (totpInput) {
      totpInput.required = true;
      totpInput.focus();
    }
  }

  function showCaptcha() {
    if (!captchaGroup || !turnstileSiteKey) return;
    captchaGroup.classList.remove('hidden');
    ensureTurnstile();
  }

  function getTurnstileResponse() {
    if (!window.turnstile || turnstileWidgetId === null) return '';
    return window.turnstile.getResponse(turnstileWidgetId);
  }

  function resetTurnstile() {
    if (window.turnstile && turnstileWidgetId !== null) {
      window.turnstile.reset(turnstileWidgetId);
    }
  }

  function ensureTurnstile() {
    if (!turnstileSiteKey || !turnstileContainer) return;
    if (turnstileWidgetId !== null) return;
    if (window.turnstile) {
      turnstileWidgetId = window.turnstile.render(turnstileContainer, { sitekey: turnstileSiteKey });
      return;
    }
    if (turnstileScriptLoading) return;
    turnstileScriptLoading = true;
    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.async = true;
    script.defer = true;
    script.onload = () => {
      turnstileScriptLoading = false;
      if (window.turnstile) {
        turnstileWidgetId = window.turnstile.render(turnstileContainer, { sitekey: turnstileSiteKey });
      }
    };
    script.onerror = () => {
      turnstileScriptLoading = false;
      showError('Captcha failed to load.');
    };
    document.head.appendChild(script);
  }

  async function loadLoginOptions() {
    try {
      const resp = await fetch('/api/auth/options');
      if (!resp.ok) return;
      const data = await resp.json();
      if (data && data.turnstileSiteKey) {
        turnstileSiteKey = String(data.turnstileSiteKey);
      }
    } catch {
      // ignore
    }
  }

  loadLoginOptions();

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();
    submitBtn.disabled = true;
    submitBtn.textContent = 'Logging in...';

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const totp = totpInput ? totpInput.value.trim() : '';

    try {
      if (captchaRequired && turnstileSiteKey) {
        const captchaToken = getTurnstileResponse();
        if (!captchaToken) {
          showError('Complete the captcha to continue.');
          submitBtn.disabled = false;
          submitBtn.textContent = 'Login';
          return;
        }
      }

      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          totp: totp || undefined,
          captchaToken: captchaRequired ? getTurnstileResponse() : undefined
        })
      });

      const data = await response.json().catch(() => ({}));

      if (response.ok) {
        // Auth cookie is set server-side (HttpOnly). Ensure no legacy tokens remain.
        try {
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          localStorage.removeItem('tokenExpires');
        } catch {
          // ignore
        }

        window.location.href = '/';
        return;
      }

      if (data && data.code === 'MFA_REQUIRED') {
        showMfa();
      }
      if (data && data.code === 'CAPTCHA_REQUIRED') {
        captchaRequired = true;
        showCaptcha();
        resetTurnstile();
      }
      showError(data.error || 'Login failed');
    } catch {
      showError('Connection error. Please try again.');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Login';
    }
  });
})();
