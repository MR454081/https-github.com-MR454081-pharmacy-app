(() => {
  const forms = document.querySelectorAll('.needs-validation');
  Array.from(forms).forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
      }
      form.classList.add('was-validated');
    });
  });
})();

(() => {
  const toggles = document.querySelectorAll('[data-toggle-password]');
  toggles.forEach((btn) => {
    btn.addEventListener('click', () => {
      const group = btn.closest('.input-group');
      const input = group ? group.querySelector('[data-password-input]') : null;
      if (!input) return;
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Hide' : 'Show';
    });
  });
})();
