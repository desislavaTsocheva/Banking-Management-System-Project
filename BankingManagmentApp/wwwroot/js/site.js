// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

//Copying the IBAN 
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-copy-iban]');
  if (!btn) return;
  const iban = btn.getAttribute('data-copy-iban');
  try {
    await navigator.clipboard.writeText(iban);
    btn.innerText = 'Copied!';
    setTimeout(() => (btn.innerText = 'Copy IBAN'), 1500);
  } catch {
    alert('Copy failed');
  }
});
