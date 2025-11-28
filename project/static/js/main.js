// Wait for the DOM to be fully loaded before running scripts
document.addEventListener('DOMContentLoaded', function () {

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
  if (deleteModal) {
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
    // --- Additional Fields Modal Logic ---
    const fieldsModal = document.getElementById('fieldsModal');
    const fieldsModalTitle = document.getElementById('fieldsModalTitle');
    const fieldsModalBody = document.getElementById('fieldsModalBody');
    const closeFieldsModal = document.getElementById('closeFieldsModal');
    const closeFieldsModalBtn = document.getElementById('closeFieldsModalBtn');

    function showFieldsModal() { fieldsModal.style.display = 'flex'; }
    function hideFieldsModal() { fieldsModal.style.display = 'none'; }

    document.querySelectorAll('.view-fields-btn').forEach(btn => {
      btn.addEventListener('click', function(e) {
        e.preventDefault();
        const entryId = this.getAttribute('data-entry-id');
        const fieldsContentWrapper = document.getElementById('fields-' + entryId);
        const siteName = this.closest('tr').querySelector('.site-name').textContent;

        if (fieldsContentWrapper && siteName) {
          // Set modal title
          fieldsModalTitle.textContent = `Fields for ${siteName}`;
          // Clone the content into the modal body
          fieldsModalBody.innerHTML = fieldsContentWrapper.innerHTML;
          // Initialize password toggles and copy buttons for the new content in the modal
          initializePasswordToggle(fieldsModalBody);
          initializeCopyButtons(fieldsModalBody);
          // Show the modal
          showFieldsModal();
        }
      });
    });

    [closeFieldsModal, closeFieldsModalBtn].forEach(el => el.addEventListener('click', hideFieldsModal));
    window.addEventListener('click', (e) => { if (e.target === fieldsModal) hideFieldsModal(); });

    // Bulk operations
    const selectAllCheckbox = document.getElementById('selectAll');
    const rowCheckboxes = document.querySelectorAll('.row-checkbox');
    const bulkActionsBar = document.getElementById('bulkActionsBar');
    const selectedCountSpan = document.getElementById('selectedCount');
    const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
    const deselectAllBtn = document.getElementById('deselectAllBtn');

    function updateBulkActionsBar() {
      const checkedCount = document.querySelectorAll('.row-checkbox:checked').length;
      if (checkedCount > 0) {
        bulkActionsBar.style.display = 'block';
        selectedCountSpan.textContent = `${checkedCount} selected`;
      } else {
        bulkActionsBar.style.display = 'none';
        selectAllCheckbox.checked = false;
      }
    }

    if (selectAllCheckbox) {
      selectAllCheckbox.addEventListener('change', function() {
        rowCheckboxes.forEach(checkbox => checkbox.checked = this.checked);
        updateBulkActionsBar();
      });

      rowCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', updateBulkActionsBar);
      });

      deselectAllBtn.addEventListener('click', function() {
        rowCheckboxes.forEach(checkbox => checkbox.checked = false);
        updateBulkActionsBar();
      });

      bulkDeleteBtn.addEventListener('click', function() {
        const selectedCheckboxes = document.querySelectorAll('.row-checkbox:checked');
        const count = selectedCheckboxes.length;
        if (count === 0) return;

        const sites = Array.from(selectedCheckboxes).map(cb => cb.getAttribute('data-site'));
        const idsToDelete = Array.from(selectedCheckboxes).map(cb => cb.getAttribute('data-entry-id'));

        const deleteMessage = document.getElementById('deleteMessage');
        const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
        const modal = document.getElementById('deleteModal');

        if (count === 1) {
          deleteMessage.textContent = `Are you sure you want to delete the password for ${sites[0]}?`;
        } else {
          deleteMessage.textContent = `Are you sure you want to delete ${count} passwords?\n\n${sites.join(', ')}`;
        }
        modal.style.display = 'flex';

        confirmDeleteBtn.onclick = function() {
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
        };
      });
    }

    // Search/Filter functionality
    const searchInput = document.getElementById('searchInput');
    const searchCount = document.getElementById('searchCount');
    const clearSearchBtn = document.getElementById('clearSearch');
    const tableRows = document.querySelectorAll('tbody tr');
    const totalRows = tableRows.length;

    function updateSearchCount() {
      const visibleRows = Array.from(tableRows).filter(row => row.style.display !== 'none').length;
      if (searchInput.value.trim()) {
        searchCount.textContent = `${visibleRows} of ${totalRows}`;
        clearSearchBtn.style.display = 'block';
      } else {
        searchCount.textContent = '';
        clearSearchBtn.style.display = 'none';
      }
    }

    if (searchInput) {
      searchInput.addEventListener('input', function() {
        const searchTerm = this.value.trim();
        const searchRegex = searchTerm ? new RegExp(`(${searchTerm.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')})`, 'gi') : null;

        tableRows.forEach(row => {
          const siteCell = row.querySelector('.site-name');
          const usernameCell = row.querySelector('.text-value');

          // Restore original text before each search
          if (siteCell && siteCell.dataset.original) {
            siteCell.innerHTML = siteCell.dataset.original;
          }
          if (usernameCell && usernameCell.dataset.original) {
            usernameCell.innerHTML = usernameCell.dataset.original;
          }

          const siteText = siteCell ? siteCell.textContent : '';
          const usernameText = usernameCell ? usernameCell.textContent : '';

          const isMatch = searchTerm ? (siteText.toLowerCase().includes(searchTerm.toLowerCase()) || usernameText.toLowerCase().includes(searchTerm.toLowerCase())) : true;

          if (isMatch && searchRegex) {
            // Store original if not already stored
            if (siteCell && !siteCell.dataset.original) siteCell.dataset.original = siteCell.innerHTML;
            if (usernameCell && !usernameCell.dataset.original) usernameCell.dataset.original = usernameCell.innerHTML;

            // Apply highlighting
            if (siteCell) siteCell.innerHTML = siteText.replace(searchRegex, `<mark class="search-highlight">$1</mark>`);
            if (usernameCell) usernameCell.innerHTML = usernameText.replace(searchRegex, `<mark class="search-highlight">$1</mark>`);
          }

          row.style.display = isMatch ? '' : 'none';
        });
        updateSearchCount();
      });

      clearSearchBtn.addEventListener('click', function() {
        searchInput.value = '';
        // Trigger the input event to clear highlights and show all rows
        searchInput.dispatchEvent(new Event('input'));
        updateSearchCount();
        searchInput.focus();
      });

      updateSearchCount();
    }

    // Export dropdown toggle
    const exportBtn = document.getElementById('exportBtn');
    const exportDropdown = document.getElementById('exportDropdown');

    if (exportBtn && exportDropdown) {
      exportBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        exportDropdown.style.display = exportDropdown.style.display === 'none' ? 'block' : 'none';
      });

      document.addEventListener('click', (e) => {
        if (!exportBtn.contains(e.target) && !exportDropdown.contains(e.target)) {
          exportDropdown.style.display = 'none';
        }
      });
    }
  }

  // --- Add/Edit Page Specific Functionality ---
  const addFieldBtn = document.getElementById('addFieldBtn');
  if (addFieldBtn) {
    let fieldCounter = document.querySelectorAll('.additional-field-row').length;
    const container = document.getElementById('additionalFieldsContainer');

    function createFieldRow(index, label = '', value = '') {
      const fieldRow = document.createElement('div');
      fieldRow.className = 'additional-field-row';
      fieldRow.innerHTML = `
        <input type="text" class="form-control" name="field_label_${index}" placeholder="Label (e.g., 2FA Code)" value="${label}">
        <input type="text" class="form-control" name="field_value_${index}" placeholder="Value" value="${value}">
        <button type="button" class="btn btn-sm btn-outline-danger remove-field-btn" title="Remove field">🗑️</button>
      `;
      fieldRow.querySelector('.remove-field-btn').addEventListener('click', () => fieldRow.remove());
      return fieldRow;
    }

    addFieldBtn.addEventListener('click', () => {
      container.appendChild(createFieldRow(fieldCounter));
      fieldCounter++;
    });

    // This part is for re-populating fields on the edit page
    const existingFieldsData = document.getElementById('existing-fields-data');
    if (existingFieldsData) {
        const fields = JSON.parse(existingFieldsData.textContent);
        fields.forEach((field, index) => {
            container.appendChild(createFieldRow(index, field.label, field.value));
            fieldCounter = index + 1;
        });
    }
  }

  // --- Form Validation ---
  const forms = document.querySelectorAll('.needs-validation');
  Array.from(forms).forEach(form => {
    form.addEventListener('submit', event => {
      const submitter = event.submitter;
      if (!submitter || !submitter.hasAttribute('formnovalidate')) {
        if (!form.checkValidity()) {
          event.preventDefault();
          event.stopPropagation();
        }
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