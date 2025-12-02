// Wait for the DOM to be fully loaded before running scripts

document.addEventListener('DOMContentLoaded', async function () {

  // Expose a global no-op refresh function (overridden on home page)
  window.refreshVault = window.refreshVault || function() {};


  // --- Client-side crypto helpers (per-user key, zero-knowledge) ---

  const encoder = new TextEncoder();

  const decoder = new TextDecoder();



  function toBase64(buffer) {

    return btoa(String.fromCharCode(...new Uint8Array(buffer)));

  }



  function fromBase64(b64) {

    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));

  }



  async function deriveKey(password, saltB64) {

    if (!password || !saltB64) return null;

    const saltBytes = fromBase64(saltB64);

    const keyMaterial = await crypto.subtle.importKey(

      'raw',

      encoder.encode(password),

      { name: 'PBKDF2' },

      false,

      ['deriveKey']

    );

    return crypto.subtle.deriveKey(

      {

        name: 'PBKDF2',

        salt: saltBytes,

        iterations: 120000,

        hash: 'SHA-256'

      },

      keyMaterial,

      { name: 'AES-GCM', length: 256 },

      true,

      ['encrypt', 'decrypt']

    );

  }



  async function exportKeyToBase64(key) {

    const raw = await crypto.subtle.exportKey('raw', key);

    return toBase64(raw);

  }



  async function importKeyFromBase64(keyB64) {

    if (!keyB64) return null;

    return crypto.subtle.importKey(

      'raw',

      fromBase64(keyB64),

      { name: 'AES-GCM' },

      false,

      ['encrypt', 'decrypt']

    );

  }



  async function storeVaultKey(key) {

    const rawB64 = await exportKeyToBase64(key);

    sessionStorage.setItem('vaultKey', rawB64);

  }



  async function getStoredVaultKey() {

    const raw = sessionStorage.getItem('vaultKey');

    if (!raw) return null;

    try {

      return await importKeyFromBase64(raw);

    } catch (err) {

      console.error('Failed to import stored key', err);

      return null;

    }

  }



  async function ensureVaultKey(promptIfMissing = true) {

    let key = await getStoredVaultKey();

    if (key) return key;



    const userSalt = document.body.dataset.userSalt;

    if (!promptIfMissing || !userSalt) return null;



    const password = window.prompt('Enter your master password to unlock your vault (never sent to the server):');

    if (!password) return null;

    key = await deriveKey(password, userSalt);

    if (key) await storeVaultKey(key);

    return key;

  }



  async function encryptPayload(key, payloadObj) {

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(

      { name: 'AES-GCM', iv },

      key,

      encoder.encode(JSON.stringify(payloadObj))

    );

    return `${toBase64(iv)}:${toBase64(ciphertext)}`;

  }



  async function decryptPayload(key, encryptedPayload) {

    if (!encryptedPayload || !encryptedPayload.includes(':')) throw new Error('Invalid payload format');

    const [ivB64, cipherB64] = encryptedPayload.split(':');

    const iv = fromBase64(ivB64);

    const cipherBytes = fromBase64(cipherB64);

    const plaintext = await crypto.subtle.decrypt(

      { name: 'AES-GCM', iv },

      key,

      cipherBytes

    );

    return JSON.parse(decoder.decode(plaintext));

  }



  async function fetchUserSalt(email) {

    const url = `/auth/salt?email=${encodeURIComponent(email)}`;

    const response = await fetch(url, { credentials: 'same-origin' });

    if (!response.ok) return null;

    const data = await response.json();

    return data.salt || null;

  }



  function collectAdditionalFields(form) {
    const fields = [];
    form.querySelectorAll('.additional-field-row').forEach(row => {
      const inputs = row.querySelectorAll('input');
      const label = inputs[0]?.value?.trim();
      const value = inputs[1]?.value || '';

      if (label && value) fields.push({ label, value });

    });

    return fields;

  }



  // --- Auth forms: derive and cache the per-user vault key in-browser ---

  const loginForm = document.querySelector('form[action="/login"]');

  if (loginForm) {

    loginForm.addEventListener('submit', async (e) => {

      const email = document.getElementById('loginEmail')?.value?.trim().toLowerCase();

      const password = document.getElementById('loginPassword')?.value || '';

      if (!email || !password) return;

      try {

        const salt = await fetchUserSalt(email);

        if (salt) {

          const key = await deriveKey(password, salt);

          if (key) await storeVaultKey(key);

        }

      } catch (err) {

        console.error('Unable to derive key on login', err);

      }

    });

  }



  const registerForm = document.querySelector('form[action="/register"]');

  if (registerForm) {

    registerForm.addEventListener('submit', async (e) => {

      const saltInput = document.getElementById('registrationSalt');

      if (saltInput && !saltInput.value) {

        const randomSalt = toBase64(crypto.getRandomValues(new Uint8Array(16)));

        saltInput.value = randomSalt;

      }

      const email = document.getElementById('registerEmail')?.value?.trim().toLowerCase();

      const password = document.getElementById('registerPassword')?.value || '';

      const salt = saltInput?.value;

      if (!email || !password || !salt) return;

      try {

        const key = await deriveKey(password, salt);

        if (key) await storeVaultKey(key);

      } catch (err) {

        console.error('Unable to derive key on registration', err);

      }

    });

  }



  function collectCategories(form) {

    const hidden = form.querySelector('#categories');

    if (!hidden || !hidden.value) return [];

    return hidden.value.split(',').map(v => v.trim()).filter(Boolean);

  }



  
  function extractDomain(siteName) {
    if (!siteName) return '';
    let site = siteName.toLowerCase().trim().replace(' login', '').replace(' account', '').replace(' app', '').trim();
    if (site.startsWith('http://') || site.startsWith('https://')) {
      try {
        const url = new URL(site);
        return url.hostname.replace(/^www\./, '');
      } catch {
        return '';
      }
    }
    if (site.startsWith('www.')) site = site.replace(/^www\./, '');
    if (site.includes('.') && !site.includes(' ')) return site;
    return `${site.split(' ')[0]}.com`;
  }
  function disablePlaintextInputs(form) {
    form.querySelectorAll('.plaintext-field').forEach(input => {
      input.removeAttribute('name');
      input.disabled = true;
      input.value = '';
    });
  }

  function disableFormInputs(form, disabled = true) {
    const skipIds = new Set(['verifyAccountPassword', 'verifySubmit', 'verifyCancel']);
    form.querySelectorAll('input, button, textarea, select').forEach(el => {
      if (skipIds.has(el.id)) return;
      if (disabled) {
        el.setAttribute('disabled', 'disabled');
      } else {
        el.removeAttribute('disabled');
      }
    });
  }

  async function verifyAccountPassword(password) {
    const resp = await fetch('/api/verify-account-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    if (!resp.ok) throw new Error('Invalid password');
    return resp.json();
  }

  async function populateEditForm(entryId, form, container) {
    const key = await ensureVaultKey();
    if (!key) throw new Error('Unlock your vault first.');
    const resp = await fetch(`/api/vault/${entryId}`);
    if (!resp.ok) throw new Error('Unable to load entry');
    const data = await resp.json();
    const payload = await decryptPayload(key, data.encrypted_payload);

    form.querySelector('#site').value = payload.site || '';
    form.querySelector('#username').value = payload.username || '';
    form.querySelector('#password').value = payload.password || '';

    const hiddenCategories = form.querySelector('#categories');
    const categories = payload.categories || data.categories || [];
    if (hiddenCategories) hiddenCategories.value = categories.join(',');
    if (window.setCategoriesFromPayload) window.setCategoriesFromPayload(categories);

    container.innerHTML = '';
    if (payload.additional_fields && payload.additional_fields.length) {
      payload.additional_fields.forEach((field, idx) => {
        container.appendChild(createFieldRow(idx, field.label, field.value));
      });
    }
  }

  function createFieldRow(index, label = '', value = '') {
    const fieldRow = document.createElement('div');
    fieldRow.className = 'additional-field-row';
    fieldRow.innerHTML = `
      <input type="text" class="form-control plaintext-field" placeholder="Label (e.g., 2FA Code)" value="${label || ''}">
      <input type="text" class="form-control plaintext-field" placeholder="Value" value="${value || ''}">
      <button type="button" class="btn btn-sm btn-outline-danger remove-field-btn" title="Remove field">Remove</button>
    `;
    fieldRow.querySelector('.remove-field-btn').addEventListener('click', () => fieldRow.remove());
    return fieldRow;
  }

  async function loadFaviconForRow(imgEl, fallbackEl, site) {
    if (!site || !imgEl) return;
    try {
      const resp = await fetch(`/api/favicon?site=${encodeURIComponent(site)}`);
      const data = await resp.json();
      if (data.url) {
        imgEl.src = data.url;
        imgEl.style.display = 'inline-block';
        if (fallbackEl) fallbackEl.style.display = 'none';
      }
    } catch (err) {
      console.error('Failed to load favicon', err);
    }
  }


  // --- General Password Toggle Functionality ---

  function initializePasswordToggle(container) {

    const toggleButtons = container.querySelectorAll('.toggle-password-btn');

    toggleButtons.forEach(function (btn) {

      btn.addEventListener('click', function () {

        const passwordInput = this.previousElementSibling;

        const iconShow = this.querySelector('.icon-show');

        const iconHide = this.querySelector('.icon-hide');

        if (!passwordInput || !iconShow || !iconHide) return; // Ensure elements exist



        if (passwordInput.type === 'password') {

          passwordInput.type = 'text';

          if (iconShow) iconShow.style.display = 'none';

          if (iconHide) iconHide.style.display = 'block';

        } else {

          passwordInput.type = 'password';

          if (iconShow) iconShow.style.display = 'block';

          if (iconHide) iconHide.style.display = 'none';

        }

      });

    });

  }

  initializePasswordToggle(document); // Run for existing elements on load



  // --- General Copy to Clipboard Functionality ---

  const toast = document.getElementById('toast');

  function initializeCopyButtons(container) {

    const copyButtons = container.querySelectorAll('.copy-btn');

    copyButtons.forEach(function(btn) {

      btn.addEventListener('click', function() {

        const textToCopy = this.getAttribute('data-copy');

        if (!textToCopy) return;



        navigator.clipboard.writeText(textToCopy).then(function() {

          if (toast) {

            toast.classList.add('show');

            setTimeout(() => toast.classList.remove('show'), 2000);

          }

        }).catch(err => console.error('Failed to copy:', err));

      });

    });

  }

  initializeCopyButtons(document); // Run for the whole document on load



  // --- General Delete Modal Functionality ---

  const deleteModal = document.getElementById('deleteModal');
  if (deleteModal && !document.querySelector('.table-container')) {
    const deleteMessage = document.getElementById('deleteMessage');

    const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');

    const cancelDeleteBtn = document.getElementById('cancelDelete');

    let deleteUrl = '';



    document.querySelectorAll('.delete-btn').forEach(function(btn) {

      btn.addEventListener('click', function(e) {

        e.preventDefault();

        const entryId = this.getAttribute('data-entry-id');

        const site = this.getAttribute('data-site');

        const isExample = this.hasAttribute('data-example');

        

        if (isExample) {

            deleteUrl = `/delete-example/${entryId}`;

        } else {

            deleteUrl = `/delete/${entryId}`;

        }



        deleteMessage.textContent = `Are you sure you want to delete the password for ${site}?`;

        deleteModal.style.display = 'flex';

      });

    });



    confirmDeleteBtn.addEventListener('click', () => {

      if (deleteUrl) window.location.href = deleteUrl;

    });



    cancelDeleteBtn.addEventListener('click', () => {

      deleteModal.style.display = 'none';

    });



    window.addEventListener('click', (e) => {

      if (e.target === deleteModal) {

        deleteModal.style.display = 'none';

      }

    });

  }



  // --- Home Page Specific Functionality (index.html) ---

  if (document.querySelector('.table-container')) {

    const fieldsModal = document.getElementById('fieldsModal');

    const fieldsModalTitle = document.getElementById('fieldsModalTitle');

    const fieldsModalBody = document.getElementById('fieldsModalBody');

    const closeFieldsModal = document.getElementById('closeFieldsModal');

    const closeFieldsModalBtn = document.getElementById('closeFieldsModalBtn');

    const deleteModal = document.getElementById('deleteModal');

    const deleteMessage = document.getElementById('deleteMessage');

    const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');

    const cancelDeleteBtn = document.getElementById('cancelDelete');

    const tableBody = document.getElementById('vaultRows');

    const rowTemplate = document.getElementById('vaultRowTemplate');

    const searchInput = document.getElementById('searchInput');

    const searchCount = document.getElementById('searchCount');

    const clearSearchBtn = document.getElementById('clearSearch');

    const selectAllCheckbox = document.getElementById('selectAll');

    const bulkActionsBar = document.getElementById('bulkActionsBar');

    const selectedCountSpan = document.getElementById('selectedCount');

    const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');

    const deselectAllBtn = document.getElementById('deselectAllBtn');

    const urlParams = new URLSearchParams(window.location.search);

    const activeCategory = urlParams.get('category');

    const sortBy = urlParams.get('sort') || 'site';



    function showFieldsModal() { fieldsModal.style.display = 'flex'; }

    function hideFieldsModal() { fieldsModal.style.display = 'none'; }



    function refreshBulkBar() {

      const checkedCount = document.querySelectorAll('.row-checkbox:checked').length;

      if (checkedCount > 0) {

        bulkActionsBar.style.display = 'block';

        selectedCountSpan.textContent = `${checkedCount} selected`;

      } else {

        bulkActionsBar.style.display = 'none';

        if (selectAllCheckbox) selectAllCheckbox.checked = false;

      }

    }



    function buildAdditionalFields(fields, entryId) {

      const wrapper = document.createElement('div');

      wrapper.className = 'fields-wrapper';

      fields.forEach(field => {

        const item = document.createElement('div');

        item.className = 'additional-field-item';

        item.innerHTML = `

          <div class="additional-field-content">

            <div class="additional-field-label">${field.label}</div>

            <div class="password-input-wrapper">

              <input type="password" class="additional-field-value-input" value="${field.value}" readonly>

              <button type="button" class="btn-icon-inline toggle-password-btn" title="Show/Hide field value">

                <svg class="icon-show" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>

                <svg class="icon-hide" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>

              </button>

              <button type="button" class="copy-btn btn-icon-inline" data-copy="${field.value}" data-type="field" title="Copy ${field.label}" style="right: 0.5rem;">

                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">

                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>

                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>

                </svg>

              </button>

            </div>

          </div>

        `;

        wrapper.appendChild(item);

      });

      const container = document.createElement('div');

      container.id = `fields-${entryId}`;

      container.className = 'fields-container';

      container.appendChild(wrapper);

      return container;

    }



  function buildRow(entry) {
    const { payload } = entry;
    const row = rowTemplate.content.firstElementChild.cloneNode(true);
    row.dataset.entryId = entry.id;
    const checkbox = row.querySelector('.row-checkbox');
      checkbox.dataset.entryId = entry.id;

      checkbox.dataset.site = payload.site || '(no site)';


    row.querySelector('.site-name').textContent = payload.site || '(no site)';
    const faviconImg = row.querySelector('.site-favicon');
    const faviconDefault = row.querySelector('.site-favicon-default');
    if (payload.site) {
      loadFaviconForRow(faviconImg, faviconDefault, payload.site);
      if (faviconImg) faviconImg.alt = payload.site;
    }
    const categoriesWrapper = row.querySelector('.category-badges');
    entry.categories.forEach(cat => {
      const badge = document.createElement('span');
      badge.className = 'category-badge';
      badge.textContent = cat;
        categoriesWrapper.appendChild(badge);

      });



      const usernameSpan = row.querySelector('.text-value');

      const usernameCopyBtn = row.querySelector('.copy-btn[data-type="username"]');

      usernameSpan.textContent = payload.username || '';

      usernameCopyBtn.dataset.copy = payload.username || '';



      const passwordInput = row.querySelector('.password-field');

      passwordInput.value = payload.password || '';

      const passwordCopyBtn = row.querySelector('.copy-btn[data-type="password"]');

      passwordCopyBtn.dataset.copy = payload.password || '';



      // Additional fields

      const fieldsBtn = row.querySelector('.view-fields-btn');

      const noFieldsPlaceholder = row.querySelector('.no-fields-placeholder');

      const fieldsContainer = row.querySelector('.fields-container');
      if (payload.additional_fields && payload.additional_fields.length > 0) {

        fieldsBtn.dataset.entryId = entry.id;

        fieldsBtn.querySelector('.field-count-text').textContent = `View ${payload.additional_fields.length} field${payload.additional_fields.length !== 1 ? 's' : ''}`;

        const builtFields = buildAdditionalFields(payload.additional_fields, entry.id);

        fieldsContainer.replaceWith(builtFields);

      } else {

        fieldsBtn.style.display = 'none';

        noFieldsPlaceholder.style.display = 'inline';

        fieldsContainer.remove();

      }



      // Actions

      const editLink = row.querySelector('.edit-link');

      editLink.href = `/edit-password/${entry.id}`;

      const deleteBtn = row.querySelector('.delete-btn');

      deleteBtn.dataset.entryId = entry.id;

      deleteBtn.dataset.site = payload.site || '(no site)';



      return row;

    }



    function renderEmpty(message) {

      tableBody.innerHTML = `<tr><td colspan="6">${message}</td></tr>`;

    }



  async function loadVault() {
    const key = await ensureVaultKey();
    if (!key) {
      renderEmpty('Vault locked. Enter your master password to unlock.');
      return;
      }



      try {

        const response = await fetch('/api/vault');

        if (!response.ok) throw new Error('Unable to fetch vault data');

        const entries = await response.json();

        const decrypted = [];



        for (const entry of entries) {

          try {

            const payload = await decryptPayload(key, entry.encrypted_payload);

            decrypted.push({ ...entry, payload });

          } catch (err) {

            console.error('Failed to decrypt entry', entry.id, err);

          }

        }



        let filtered = decrypted;

        if (activeCategory) {

          filtered = filtered.filter(e => e.categories.includes(activeCategory));

        }



        filtered.sort((a, b) => {

          if (sortBy === 'date_added') {

            return new Date(b.date_added) - new Date(a.date_added);

          }

          return (a.payload.site || '').localeCompare(b.payload.site || '');

        });



        tableBody.innerHTML = '';

        if (filtered.length === 0) {

          renderEmpty('No passwords found for this filter.');

          return;

        }



        filtered.forEach(entry => tableBody.appendChild(buildRow(entry)));

        initializePasswordToggle(tableBody);

        initializeCopyButtons(tableBody);

        refreshBulkBar();

      } catch (err) {

        console.error(err);

        renderEmpty('Unable to load vault entries.');

      }

    }



    // Event delegation for delete + additional fields

    document.addEventListener('click', (e) => {
      const deleteBtn = e.target.closest('.delete-btn');
      if (deleteBtn) {
        e.preventDefault();
        const site = deleteBtn.getAttribute('data-site');
        const entryId = deleteBtn.dataset.entryId;
        deleteMessage.textContent = `Are you sure you want to delete the password for ${site}?`;
        deleteModal.dataset.deleteUrl = `/delete/${entryId}`;
        deleteModal.dataset.entryId = entryId;
        deleteModal.style.display = 'flex';
      }


      const fieldsBtnClick = e.target.closest('.view-fields-btn');

      if (fieldsBtnClick) {

        e.preventDefault();

        const entryId = fieldsBtnClick.getAttribute('data-entry-id');

        const fieldsContentWrapper = document.getElementById('fields-' + entryId);

        const siteName = fieldsBtnClick.closest('tr').querySelector('.site-name').textContent;



        if (fieldsContentWrapper && siteName) {

          fieldsModalTitle.textContent = `Fields for ${siteName}`;

          fieldsModalBody.innerHTML = fieldsContentWrapper.innerHTML;

          initializePasswordToggle(fieldsModalBody);

          initializeCopyButtons(fieldsModalBody);

          showFieldsModal();

        }

      }

    });



    [closeFieldsModal, closeFieldsModalBtn].forEach(el => el && el.addEventListener('click', hideFieldsModal));

    window.addEventListener('click', (e) => { if (e.target === fieldsModal) hideFieldsModal(); });



    if (cancelDeleteBtn) {

      cancelDeleteBtn.addEventListener('click', () => { deleteModal.style.display = 'none'; });

    }

    if (confirmDeleteBtn) {
      confirmDeleteBtn.addEventListener('click', () => {
        const entryId = deleteModal.dataset.entryId;
        if (!entryId) return;
        fetch(`/api/vault/${entryId}`, { method: 'DELETE' })
          .then(() => {
            deleteModal.style.display = 'none';
            loadVault();
          })
          .catch(() => window.location.href = `/delete/${entryId}`); // fallback
      });
    }
    window.addEventListener('click', (e) => { if (e.target === deleteModal) deleteModal.style.display = 'none'; });



    if (selectAllCheckbox) {

      selectAllCheckbox.addEventListener('change', function() {

        document.querySelectorAll('.row-checkbox').forEach(checkbox => checkbox.checked = this.checked);

        refreshBulkBar();

      });

    }

    if (deselectAllBtn) {

      deselectAllBtn.addEventListener('click', function() {

        document.querySelectorAll('.row-checkbox').forEach(checkbox => checkbox.checked = false);

        refreshBulkBar();

      });

    }

    document.addEventListener('change', (e) => {

      if (e.target.classList.contains('row-checkbox')) refreshBulkBar();

    });



    if (bulkDeleteBtn) {
      bulkDeleteBtn.addEventListener('click', function() {
        const selectedCheckboxes = document.querySelectorAll('.row-checkbox:checked');
        const count = selectedCheckboxes.length;
        if (count === 0) return;


        const sites = Array.from(selectedCheckboxes).map(cb => cb.getAttribute('data-site'));

        const idsToDelete = Array.from(selectedCheckboxes).map(cb => cb.getAttribute('data-entry-id'));



        if (count === 1) {
          deleteMessage.textContent = `Are you sure you want to delete the password for ${sites[0]}?`;
        } else {
          deleteMessage.textContent = `Are you sure you want to delete ${count} passwords?\n\n${sites.join(', ')}`;
        }
        deleteModal.dataset.deleteUrl = null;
        deleteModal.style.display = 'flex';
        confirmDeleteBtn.onclick = function() {
          fetch('/api/vault/bulk-delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: idsToDelete })
          }).then(() => {
            deleteModal.style.display = 'none';
            loadVault();
          }).catch(() => {
            // fallback to old form submission
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/bulk-delete';
            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = document.querySelector('input[name="csrf_token"]').value;
            form.appendChild(csrfInput);
            const idsInput = document.createElement('input');
            idsInput.type = 'hidden';
            idsInput.name = 'entry_ids';
            idsInput.value = JSON.stringify(idsToDelete);
            form.appendChild(idsInput);
            document.body.appendChild(form);
            form.submit();
          });
        };
      });
    }


    // Search/Filter functionality (client-side)

    function performSearch() {

      const term = searchInput.value.trim();

      const regex = term ? new RegExp(`(${term.replace(/[-\\/\\^$*+?.()|[\\]{}]/g, '\\\\$&')})`, 'gi') : null;

      const rows = Array.from(tableBody.querySelectorAll('tr'));

      const totalRows = rows.length;



      rows.forEach(row => {

        const siteCell = row.querySelector('.site-name');

        const usernameCell = row.querySelector('.text-value');



        if (siteCell && siteCell.dataset.original) siteCell.innerHTML = siteCell.dataset.original;

        if (usernameCell && usernameCell.dataset.original) usernameCell.innerHTML = usernameCell.dataset.original;



        const siteText = siteCell ? siteCell.textContent : '';

        const usernameText = usernameCell ? usernameCell.textContent : '';

        const isMatch = term ? (siteText.toLowerCase().includes(term.toLowerCase()) || usernameText.toLowerCase().includes(term.toLowerCase())) : true;



        if (isMatch && regex) {

          if (siteCell && !siteCell.dataset.original) siteCell.dataset.original = siteCell.innerHTML;

          if (usernameCell && !usernameCell.dataset.original) usernameCell.dataset.original = usernameCell.innerHTML;



          if (siteCell) siteCell.innerHTML = siteText.replace(regex, `<mark class="search-highlight">$1</mark>`);

          if (usernameCell) usernameCell.innerHTML = usernameText.replace(regex, `<mark class="search-highlight">$1</mark>`);

        }

        row.style.display = isMatch ? '' : 'none';

      });



      const visibleRows = rows.filter(r => r.style.display !== 'none').length;

      if (term) {

        searchCount.textContent = `${visibleRows} of ${totalRows}`;

        clearSearchBtn.style.display = 'block';

      } else {

        searchCount.textContent = '';

        clearSearchBtn.style.display = 'none';

      }

    }



    if (searchInput) {

      searchInput.addEventListener('input', performSearch);

      clearSearchBtn.addEventListener('click', () => {

        searchInput.value = '';

        performSearch();

        searchInput.focus();

      });

    }



    await loadVault();
    window.refreshVault = loadVault;
  }


  // --- Add/Edit Page Specific Functionality ---
  const addFieldBtn = document.getElementById('addFieldBtn');
  if (addFieldBtn) {
    let fieldCounter = document.querySelectorAll('.additional-field-row').length;
    const container = document.getElementById('additionalFieldsContainer');

    addFieldBtn.addEventListener('click', () => {
      container.appendChild(createFieldRow(fieldCounter));
      fieldCounter++;
    });

    const existingFieldsData = document.getElementById('existing-fields-data');
    if (existingFieldsData) {
        const fields = JSON.parse(existingFieldsData.textContent);
        fields.forEach((field, index) => {
            container.appendChild(createFieldRow(index, field.label, field.value));
            fieldCounter = index + 1;
        });
    }
  }

  // --- Edit form verification + populate ---
  const editForm = document.querySelector('form[data-entry-id]');
  if (editForm && editForm.dataset.entryId) {
    const verifyModal = document.getElementById('verifyModal');
    const verifyBtn = document.getElementById('verifySubmit');
    const verifyCancel = document.getElementById('verifyCancel');
    const verifyInput = document.getElementById('verifyAccountPassword');
    const verifyError = document.getElementById('verifyError');
    const fieldsContainer = document.getElementById('additionalFieldsContainer');

    const requireVerify = editForm.dataset.requiresVerify === 'true';
    if (requireVerify && verifyModal) {
      verifyModal.style.display = 'flex';
      if (verifyInput) verifyInput.focus();
      disableFormInputs(editForm, true);

      const handleVerify = async () => {
        verifyError.style.display = 'none';
        try {
          let pwd = verifyInput?.value || '';
          if (!pwd) {
            pwd = window.prompt('Enter your account password to continue:') || '';
          }
          if (!pwd) throw new Error('Missing password');
          await verifyAccountPassword(pwd);
          verifyModal.style.display = 'none';
          disableFormInputs(editForm, false);
          await populateEditForm(editForm.dataset.entryId, editForm, fieldsContainer);
        } catch (err) {
          verifyError.textContent = 'Incorrect password. Please try again.';
          verifyError.style.display = 'block';
        }
      };

      if (verifyBtn) verifyBtn.addEventListener('click', handleVerify);
      if (verifyInput) verifyInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') handleVerify(); });
      if (verifyCancel) verifyCancel.addEventListener('click', () => {
        verifyModal.style.display = 'none';
        window.location.href = '/home';
      });
    } else {
      populateEditForm(editForm.dataset.entryId, editForm, fieldsContainer).catch(err => console.error(err));
    }
  }

// --- Form Validation ---

  const forms = document.querySelectorAll('.needs-validation');
  Array.from(forms).forEach(form => {
    form.addEventListener('submit', async event => {
      const submitter = event.submitter;
      const requiresValidation = !submitter || !submitter.hasAttribute('formnovalidate');
      if (requiresValidation && !form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
        form.classList.add('was-validated');
        return;
      }

      if (form.dataset.encrypt === 'vault') {
        event.preventDefault();
        form.classList.add('was-validated');

        const key = await ensureVaultKey();
        if (!key) {
          alert('Your master password is required to encrypt this entry locally.');
          return;
        }

        const payload = {
          site: form.querySelector('#site')?.value?.trim() || '',
          username: form.querySelector('#username')?.value?.trim() || '',
          password: form.querySelector('#password')?.value || '',
          additional_fields: collectAdditionalFields(form),
          categories: collectCategories(form)
        };

        try {
          const encrypted = await encryptPayload(key, payload);
          const hiddenInput = form.querySelector('#encrypted_payload');
          if (!hiddenInput) {
            alert('Missing encrypted payload field.');
            return;
          }
          hiddenInput.value = encrypted;
          disablePlaintextInputs(form);

          const entryId = form.dataset.entryId;
          const url = entryId ? `/api/vault/${entryId}` : '/api/vault';
          const method = entryId ? 'PUT' : 'POST';
          const body = JSON.stringify({
            encrypted_payload: encrypted,
            categories: collectCategories(form),
            site: payload.site
          });
          const headers = { 'Content-Type': 'application/json' };

          fetch(url, { method, headers, body })
            .then(resp => {
              if (!resp.ok) throw new Error('Save failed');
              return resp.json();
            })
            .then(() => {
              // If the vault page is present, refresh in place; otherwise fall back to navigating home.
              if (typeof window.refreshVault === 'function') {
                window.refreshVault();
                // If we're on a standalone form page, go back to home after refreshing
                if (!document.querySelector('.table-container')) {
                  window.location.href = '/home';
                }
              } else {
                window.location.href = '/home';
              }
            })
            .catch(err => {
              console.error(err);
              form.submit(); // fallback to old behavior
            });
        } catch (err) {
          console.error('Failed to encrypt payload', err);
          alert('Encryption failed. Please try again.');
        }
        return;
      }



      form.classList.add('was-validated');

    }, false);

  });



  // --- Session Timeout (from base.html) ---

  const timeoutModal = document.getElementById('timeoutModal');

  if (timeoutModal) {

    let inactivityTimeout;

    const TIMEOUT_DURATION = 15 * 60 * 1000; // 15 minutes



    function showTimeoutModal() {

      timeoutModal.style.display = 'flex';

      document.getElementById('timeoutOkBtn').addEventListener('click', () => window.location.href = '/logout');

      setTimeout(() => window.location.href = '/logout', 5000);

    }



    function resetInactivityTimer() {

      clearTimeout(inactivityTimeout);

      inactivityTimeout = setTimeout(showTimeoutModal, TIMEOUT_DURATION);

    }



    ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'].forEach(eventName => {

      document.addEventListener(eventName, resetInactivityTimer, true);

    });



    resetInactivityTimer();

  }

});



// --- Password Generation via API ---

document.querySelectorAll('.generate-password-api-btn').forEach(button => {

  button.addEventListener('click', function() {

    const targetInputId = this.getAttribute('data-target');

    const passwordInput = document.getElementById(targetInputId);



    if (passwordInput) {

      fetch('/generate-password')

        .then(response => response.json())

        .then(data => {

          if (data.password) {

            passwordInput.value = data.password;

            // Optional: Trigger a visual feedback

            passwordInput.style.backgroundColor = '#e0e7ff';

            setTimeout(() => { passwordInput.style.backgroundColor = ''; }, 500);

          }

        })

        .catch(error => console.error('Error fetching new password:', error));

    }

  });

});



// --- Category Tag Input Functionality ---

const tagInputWrapper = document.querySelector('.tag-input-wrapper');

if (tagInputWrapper) {

  const categoryInput = document.getElementById('category-input');

  const tagContainer = document.getElementById('tag-container');

  const suggestionBox = document.getElementById('suggestion-box');

  const hiddenCategoriesInput = document.getElementById('categories');



  let allCategories = [];
  let selectedCategories = new Set();

  // Expose helper so edit page can seed categories after decryption
  window.setCategoriesFromPayload = function(categories) {
    if (!Array.isArray(categories)) return;
    selectedCategories = new Set();
    tagContainer.innerHTML = '';
    categories.forEach(cat => createTag(cat));
    updateHiddenInput();
  };


  // Fetch all categories from the API

  fetch('/api/categories')

    .then(response => response.json())

    .then(data => {

      allCategories = data;

    });



  function updateHiddenInput() {

    hiddenCategoriesInput.value = Array.from(selectedCategories).join(',');

  }



  function createTag(label) {

    if (selectedCategories.has(label) || !label) return;



    const tag = document.createElement('div');

    tag.className = 'tag-pill';

    tag.textContent = label;



    const closeBtn = document.createElement('span');

    closeBtn.className = 'tag-close';

    closeBtn.innerHTML = '&times;';

    closeBtn.addEventListener('click', () => {

      tag.remove();

      selectedCategories.delete(label);

      updateHiddenInput();

    });



    tag.appendChild(closeBtn);

    tagContainer.appendChild(tag);

    selectedCategories.add(label);

    updateHiddenInput();

  }



  // Populate initial tags from hidden input (for edit page)

  if (hiddenCategoriesInput.value) {

    hiddenCategoriesInput.value.split(',').forEach(cat => {

      if (cat.trim()) createTag(cat.trim());

    });

  }



  categoryInput.addEventListener('input', () => {

    const inputValue = categoryInput.value.toLowerCase();

    if (!inputValue) {

      suggestionBox.style.display = 'none';

      return;

    }



    const suggestions = allCategories.filter(cat =>

      cat.toLowerCase().includes(inputValue) && !selectedCategories.has(cat)

    );



    suggestionBox.innerHTML = '';

    if (suggestions.length > 0) {

      suggestions.forEach(suggestion => {

        const suggestionItem = document.createElement('div');

        suggestionItem.className = 'suggestion-item';

        suggestionItem.textContent = suggestion;

        suggestionItem.addEventListener('click', () => {

          createTag(suggestion);

          categoryInput.value = '';

          suggestionBox.style.display = 'none';

          categoryInput.focus();

        });

        suggestionBox.appendChild(suggestionItem);

      });

      suggestionBox.style.display = 'block';

    } else {

      suggestionBox.style.display = 'none';

    }

  });



  categoryInput.addEventListener('keydown', (e) => {

    if (e.key === 'Enter' || e.key === ',') {

      e.preventDefault();

      const newTag = categoryInput.value.trim();

      if (newTag) {

        createTag(newTag);

        categoryInput.value = '';

        suggestionBox.style.display = 'none';

      }

    }

  });



  // Hide suggestions when clicking outside

  document.addEventListener('click', (e) => {

    if (!tagInputWrapper.contains(e.target)) {

      suggestionBox.style.display = 'none';

    }

  });



  // Focus input when clicking the wrapper

  tagInputWrapper.addEventListener('click', (e) => {

    if (e.target === tagInputWrapper || e.target === tagContainer) {

      categoryInput.focus();

    }

  });

}

