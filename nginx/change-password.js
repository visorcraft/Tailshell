(function () {
  const form = document.getElementById('changePasswordForm');
  const errorDiv = document.getElementById('error');
  const successDiv = document.getElementById('success');
  const submitBtn = document.getElementById('submitBtn');

  function showError(message) {
    successDiv.classList.remove('visible');
    errorDiv.textContent = message;
    errorDiv.classList.add('visible');
  }

  function showSuccess(message) {
    errorDiv.classList.remove('visible');
    successDiv.textContent = message;
    successDiv.classList.add('visible');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorDiv.classList.remove('visible');
    successDiv.classList.remove('visible');

    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (!currentPassword || !newPassword || !confirmPassword) {
      showError('All fields are required.');
      return;
    }

    if (newPassword.length < 8) {
      showError('New password must be at least 8 characters.');
      return;
    }

    if (newPassword !== confirmPassword) {
      showError('New passwords do not match.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Changing...';

    try {
      const response = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword })
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        if (response.status === 401) {
          showError('You must log in first.');
          return;
        }
        showError(data.error || 'Failed to change password.');
        return;
      }

      showSuccess('Password changed. Redirecting…');
      setTimeout(() => {
        window.location.href = '/';
      }, 600);
    } catch {
      showError('Connection error. Please try again.');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Change password';
    }
  });
})();

