(function () {
  'use strict';

  var APP_KEY = 'webapp_passwordBuddy';
  var APP_VERSION = '001.001';
  var KDF_KEY = APP_KEY + '.kdf.v1';
  var VAULT_KEY = APP_KEY + '.vault.v1';
  var ACTIVE_BOOK_KEY = APP_KEY + '.activeBook.v1';
  var ENTRY_VIEW_KEY = APP_KEY + '.entryView.v1';

  var PBKDF2_ITERATIONS = 210000;
  var VERIFIER_PLAINTEXT = 'passwordBuddy-verify-v1';
  var TOTP_PERIOD = 30;
  var TOTP_DIGITS = 6;
  var OTP_RING_RADIUS = 10;
  var BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  var ICONS = Buddy.ICONS;
  var escapeHtml = Buddy.escapeHtml;

  var dom = {};
  var state = {
    masterKey: null,
    vault: { version: 1, books: [], entries: [] },
    activeBookId: null,
    search: '',
    tagFilter: [],
    entryView: loadEntryView(),
    otpPlainCache: Object.create(null),
    otpTimer: null
  };

  var modalApi = Buddy.modal.init();
  var openModal = modalApi.open;
  var closeModal = modalApi.close;

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    cacheDom();
    initStaticIcons();
    bindAuthEvents();
    bindAppEvents();

    if (loadKdf()) {
      showAuthView('unlock');
    } else {
      showAuthView('setup');
    }
  }

  function cacheDom() {
    dom.authScreen = document.getElementById('authScreen');

    dom.authViewSetup = document.getElementById('authViewSetup');
    dom.setupPassword = document.getElementById('setupPassword');
    dom.setupPasswordConfirm = document.getElementById('setupPasswordConfirm');
    dom.setupError = document.getElementById('setupError');
    dom.setupWarningIcon = document.getElementById('setupWarningIcon');
    dom.btnSetup = document.getElementById('btnSetup');

    dom.authViewUnlock = document.getElementById('authViewUnlock');
    dom.unlockPassword = document.getElementById('unlockPassword');
    dom.unlockError = document.getElementById('unlockError');
    dom.btnUnlock = document.getElementById('btnUnlock');
    dom.btnResetApp = document.getElementById('btnResetApp');

    dom.appRoot = document.getElementById('appRoot');
    dom.lockMenuWrap = document.getElementById('lockMenuWrap');
    dom.btnLock = document.getElementById('btnLock');
    dom.lockMenu = document.getElementById('lockMenu');
    dom.menuLock = document.getElementById('menuLock');
    dom.menuLockIcon = document.getElementById('menuLockIcon');
    dom.menuChangeMasterKey = document.getElementById('menuChangeMasterKey');
    dom.menuChangeMasterKeyIcon = document.getElementById('menuChangeMasterKeyIcon');
    dom.btnSettings = document.getElementById('btnSettings');

    dom.btnAddBook = document.getElementById('btnAddBook');
    dom.btnExportAll = document.getElementById('btnExportAll');
    dom.fileImportData = document.getElementById('fileImportData');
    dom.fileBtnIcon = document.getElementById('fileBtnIcon');
    dom.bookList = document.getElementById('bookList');
    dom.bookListEmpty = document.getElementById('bookListEmpty');
    dom.linkLoadSampleSidebar = document.getElementById('linkLoadSampleSidebar');

    dom.emptyState = document.getElementById('emptyState');
    dom.entriesContent = document.getElementById('entriesContent');
    dom.activeBookName = document.getElementById('activeBookName');
    dom.entriesCount = document.getElementById('entriesCount');
    dom.entrySearch = document.getElementById('entrySearch');
    dom.tagFilterDropdown = document.getElementById('tagFilterDropdown');
    dom.btnToggleEntryView = document.getElementById('btnToggleEntryView');
    dom.btnNewEntry = document.getElementById('btnNewEntry');
    dom.entriesEmpty = document.getElementById('entriesEmpty');
    dom.entryGrid = document.getElementById('entryGrid');
  }

  function initStaticIcons() {
    dom.setupWarningIcon.innerHTML = ICONS.alertTriangle;
    dom.btnLock.innerHTML = ICONS.lock;
    dom.menuLockIcon.innerHTML = ICONS.lock;
    dom.menuChangeMasterKeyIcon.innerHTML = ICONS.key;
    dom.btnSettings.innerHTML = ICONS.settings;
    dom.btnExportAll.innerHTML = ICONS.download;
    dom.fileBtnIcon.innerHTML = ICONS.upload;
    applyEntryViewMode();
  }

  function bytesToB64(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function randomBytes(len) {
    var arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return arr;
  }

  async function deriveKey(password, saltBytes, iterations) {
    var enc = new TextEncoder();
    var baseKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptField(key, plaintext) {
    var iv = randomBytes(12);
    var enc = new TextEncoder();
    var ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(plaintext));
    return 'enc:v1:' + bytesToB64(iv) + ':' + bytesToB64(new Uint8Array(ctBuf));
  }

  async function decryptField(key, packed) {
    var parts = String(packed || '').split(':');
    if (parts.length !== 4 || parts[0] !== 'enc' || parts[1] !== 'v1') {
      throw new Error('Not an encrypted field');
    }
    var iv = b64ToBytes(parts[2]);
    var ct = b64ToBytes(parts[3]);
    var ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
    return new TextDecoder().decode(ptBuf);
  }

  function makeVerifier(key) {
    return encryptField(key, VERIFIER_PLAINTEXT);
  }

  async function checkVerifier(key, verifier) {
    try {
      var pt = await decryptField(key, verifier);
      return pt === VERIFIER_PLAINTEXT;
    } catch (e) {
      return false;
    }
  }

  function base32Decode(input) {
    var clean = String(input || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
    var bits = '';
    for (var i = 0; i < clean.length; i++) {
      var val = BASE32_ALPHABET.indexOf(clean.charAt(i));
      if (val === -1) continue;
      var bin = val.toString(2);
      while (bin.length < 5) bin = '0' + bin;
      bits += bin;
    }
    var bytes = [];
    for (var j = 0; j + 8 <= bits.length; j += 8) {
      bytes.push(parseInt(bits.substr(j, 8), 2));
    }
    return new Uint8Array(bytes);
  }

  async function totpCode(secretBase32, unixSeconds) {
    var keyBytes = base32Decode(secretBase32);
    if (!keyBytes.length) return null;

    var counter = Math.floor(unixSeconds / TOTP_PERIOD);
    var counterBuf = new ArrayBuffer(8);
    var view = new DataView(counterBuf);
    view.setUint32(0, Math.floor(counter / 0x100000000));
    view.setUint32(4, counter >>> 0);

    var cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    var sigBuf = await crypto.subtle.sign('HMAC', cryptoKey, counterBuf);
    var sig = new Uint8Array(sigBuf);
    var offset = sig[sig.length - 1] & 0x0f;
    var binCode = ((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) |
      ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff);
    var code = String(binCode % Math.pow(10, TOTP_DIGITS));
    while (code.length < TOTP_DIGITS) code = '0' + code;
    return code;
  }

  function totpSecondsRemaining(unixSeconds) {
    return TOTP_PERIOD - (Math.floor(unixSeconds) % TOTP_PERIOD);
  }

  function loadKdf() {
    try {
      var raw = localStorage.getItem(KDF_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function saveKdf(kdf) {
    try { localStorage.setItem(KDF_KEY, JSON.stringify(kdf)); } catch (e) {}
  }

  function loadVaultRaw() {
    try {
      var raw = localStorage.getItem(VAULT_KEY);
      var v = raw ? JSON.parse(raw) : null;
      if (!v || !Array.isArray(v.books) || !Array.isArray(v.entries)) return { version: 1, books: [], entries: [] };
      return v;
    } catch (e) {
      return { version: 1, books: [], entries: [] };
    }
  }

  function saveVaultRaw(vault) {
    try { localStorage.setItem(VAULT_KEY, JSON.stringify(vault)); } catch (e) {}
  }

  function persistVault() {
    saveVaultRaw(state.vault);
  }

  function loadActiveBookId() {
    try { return localStorage.getItem(ACTIVE_BOOK_KEY); } catch (e) { return null; }
  }

  function saveActiveBookId(id) {
    try {
      if (id) localStorage.setItem(ACTIVE_BOOK_KEY, id);
      else localStorage.removeItem(ACTIVE_BOOK_KEY);
    } catch (e) {}
  }

  function loadEntryView() {
    try { return localStorage.getItem(ENTRY_VIEW_KEY) === 'list' ? 'list' : 'grid'; } catch (e) { return 'grid'; }
  }

  function saveEntryView(view) {
    try { localStorage.setItem(ENTRY_VIEW_KEY, view); } catch (e) {}
  }

  function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  }

  function bindAuthEvents() {
    dom.btnSetup.addEventListener('click', handleSetupSubmit);
    dom.setupPasswordConfirm.addEventListener('keydown', function (e) { if (e.key === 'Enter') handleSetupSubmit(); });
    dom.btnUnlock.addEventListener('click', handleUnlockSubmit);
    dom.unlockPassword.addEventListener('keydown', function (e) { if (e.key === 'Enter') handleUnlockSubmit(); });
    dom.btnResetApp.addEventListener('click', handleResetApp);
  }

  function showAuthView(mode) {
    dom.authViewSetup.hidden = mode !== 'setup';
    dom.authViewUnlock.hidden = mode !== 'unlock';
    if (mode === 'unlock') {
      dom.unlockPassword.value = '';
      dom.unlockError.hidden = true;
      setTimeout(function () { dom.unlockPassword.focus(); }, 0);
    } else {
      dom.setupPassword.value = '';
      dom.setupPasswordConfirm.value = '';
      dom.setupError.hidden = true;
      setTimeout(function () { dom.setupPassword.focus(); }, 0);
    }
  }

  function showAuthError(which, msg) {
    var el = which === 'setup' ? dom.setupError : dom.unlockError;
    el.textContent = msg;
    el.hidden = false;
  }

  async function handleSetupSubmit() {
    var pw = dom.setupPassword.value;
    var confirmPw = dom.setupPasswordConfirm.value;
    if (pw.length < 8) { showAuthError('setup', 'Master key must be at least 8 characters.'); return; }
    if (pw !== confirmPw) { showAuthError('setup', 'Master keys do not match.'); return; }

    dom.btnSetup.disabled = true;
    try {
      var salt = randomBytes(16);
      var key = await deriveKey(pw, salt, PBKDF2_ITERATIONS);
      var verifier = await makeVerifier(key);
      saveKdf({ salt: bytesToB64(salt), iterations: PBKDF2_ITERATIONS, verifier: verifier });

      var vault = { version: 1, books: [], entries: [] };
      saveVaultRaw(vault);

      state.masterKey = key;
      state.vault = vault;
      state.activeBookId = null;
      saveActiveBookId(null);
      enterApp();
    } catch (e) {
      showAuthError('setup', 'Could not create your vault. Please try again.');
    } finally {
      dom.btnSetup.disabled = false;
    }
  }

  async function handleUnlockSubmit() {
    var pw = dom.unlockPassword.value;
    var kdf = loadKdf();
    if (!kdf) { showAuthView('setup'); return; }

    dom.btnUnlock.disabled = true;
    try {
      var salt = b64ToBytes(kdf.salt);
      var key = await deriveKey(pw, salt, kdf.iterations);
      var ok = await checkVerifier(key, kdf.verifier);
      if (!ok) {
        showAuthError('unlock', 'Incorrect master key.');
        return;
      }
      state.masterKey = key;
      state.vault = loadVaultRaw();
      state.activeBookId = loadActiveBookId();
      if (!state.activeBookId || !findBook(state.activeBookId)) {
        state.activeBookId = state.vault.books.length ? state.vault.books[0].id : null;
      }
      enterApp();
    } catch (e) {
      showAuthError('unlock', 'Incorrect master key.');
    } finally {
      dom.btnUnlock.disabled = false;
    }
  }

  function handleResetApp() {
    openConfirmModal(
      'Reset App Data',
      'This permanently deletes your master key and ALL saved passwords stored in this browser. This cannot be undone.',
      'Delete Everything',
      function () {
        try {
          localStorage.removeItem(KDF_KEY);
          localStorage.removeItem(VAULT_KEY);
          localStorage.removeItem(ACTIVE_BOOK_KEY);
        } catch (e) {}
        showAuthView('setup');
      },
      { danger: true }
    );
  }

  function enterApp() {
    dom.authScreen.hidden = true;
    dom.appRoot.hidden = false;
    renderBookList();
    selectBook(state.activeBookId);
    startOtpTicker();
  }

  function handleLock() {
    stopOtpTicker();
    state.masterKey = null;
    state.otpPlainCache = Object.create(null);
    dom.appRoot.hidden = true;
    dom.authScreen.hidden = false;
    showAuthView('unlock');
  }

  function bindAppEvents() {
    dom.btnLock.addEventListener('click', function (e) {
      e.stopPropagation();
      toggleLockMenu();
    });
    dom.menuLock.addEventListener('click', function () {
      closeLockMenu();
      handleLock();
    });
    dom.menuChangeMasterKey.addEventListener('click', function () {
      closeLockMenu();
      openChangeMasterKeyModal();
    });
    document.addEventListener('click', function (e) {
      if (!dom.lockMenuWrap.contains(e.target)) closeLockMenu();
      document.querySelectorAll('.dropdown.open').forEach(function (dd) {
        if (dd.contains(e.target)) return;
        dd.classList.remove('open');
        var menu = dd.querySelector('.dropdown-menu');
        if (menu) menu.hidden = true;
        var toggle = dd.querySelector('.dropdown-toggle');
        if (toggle) toggle.setAttribute('aria-expanded', 'false');
      });
    });

    dom.btnSettings.addEventListener('click', openSettingsModal);

    dom.btnAddBook.addEventListener('click', handleAddBook);
    dom.btnExportAll.addEventListener('click', exportAllData);
    dom.fileImportData.addEventListener('change', function () {
      var file = this.files[0];
      if (file) importDataFromFile(file);
      this.value = '';
    });

    dom.entrySearch.addEventListener('input', function () {
      state.search = dom.entrySearch.value;
      renderEntryGrid();
    });
    dom.btnToggleEntryView.addEventListener('click', toggleEntryView);
    dom.btnNewEntry.addEventListener('click', function () { openEntryModal(null); });
    dom.linkLoadSampleSidebar.addEventListener('click', handleLoadSample);
  }

  function applyEntryViewMode() {
    var isList = state.entryView === 'list';
    dom.entryGrid.classList.toggle('list-view', isList);
    dom.btnToggleEntryView.innerHTML = isList ? ICONS.grid : ICONS.list;
    dom.btnToggleEntryView.title = isList ? 'Switch to grid view' : 'Switch to list view';
    dom.btnToggleEntryView.setAttribute('aria-label', dom.btnToggleEntryView.title);
    dom.btnToggleEntryView.setAttribute('aria-pressed', String(isList));
  }

  function toggleEntryView() {
    state.entryView = state.entryView === 'list' ? 'grid' : 'list';
    saveEntryView(state.entryView);
    applyEntryViewMode();
    if (!dom.entriesContent.hidden) renderEntryGrid();
  }

  function toggleLockMenu() {
    var isOpen = dom.lockMenuWrap.classList.contains('open');
    if (isOpen) closeLockMenu();
    else openLockMenu();
  }

  function openLockMenu() {
    dom.lockMenuWrap.classList.add('open');
    dom.lockMenu.hidden = false;
    dom.btnLock.setAttribute('aria-expanded', 'true');
  }

  function closeLockMenu() {
    dom.lockMenuWrap.classList.remove('open');
    dom.lockMenu.hidden = true;
    dom.btnLock.setAttribute('aria-expanded', 'false');
  }

  function findBook(id) {
    return state.vault.books.filter(function (b) { return b.id === id; })[0];
  }

  function booksSorted() {
    return state.vault.books.slice().sort(function (a, b) { return a.createdAt - b.createdAt; });
  }

  function entriesForBook(bookId) {
    return state.vault.entries.filter(function (e) { return e.bookId === bookId; });
  }

  function handleAddBook() {
    openPromptModal('Add Book', 'Book name', '', function (name) {
      name = (name || '').trim();
      if (!name) return;
      var book = { id: generateId(), name: name, createdAt: Date.now() };
      state.vault.books.push(book);
      persistVault();
      state.activeBookId = book.id;
      saveActiveBookId(book.id);
      renderBookList();
      selectBook(book.id);
    });
  }

  function handleRenameBook(id) {
    var book = findBook(id);
    if (!book) return;
    openPromptModal('Rename Book', 'Book name', book.name, function (name) {
      name = (name || '').trim();
      if (!name) return;
      book.name = name;
      persistVault();
      renderBookList();
      if (state.activeBookId === id) dom.activeBookName.textContent = name;
    });
  }

  function handleDeleteBook(id) {
    var book = findBook(id);
    if (!book) return;
    var count = entriesForBook(id).length;
    var msg = count > 0
      ? 'Delete "' + book.name + '" and its ' + count + ' saved password' + (count === 1 ? '' : 's') + '? This cannot be undone.'
      : 'Delete "' + book.name + '"? This cannot be undone.';
    openConfirmModal('Delete Book', msg, 'Delete', function () {
      state.vault.books = state.vault.books.filter(function (b) { return b.id !== id; });
      state.vault.entries = state.vault.entries.filter(function (e) { return e.bookId !== id; });
      persistVault();
      if (state.activeBookId === id) {
        var remaining = booksSorted();
        state.activeBookId = remaining.length ? remaining[0].id : null;
        saveActiveBookId(state.activeBookId);
      }
      renderBookList();
      selectBook(state.activeBookId);
    }, { danger: true });
  }

  function renderBookList() {
    var books = booksSorted();
    dom.bookListEmpty.hidden = books.length > 0;
    dom.bookList.innerHTML = books.map(function (b) {
      return '<li class="book-item' + (b.id === state.activeBookId ? ' active' : '') + '" data-id="' + b.id + '">' +
        '<span class="book-item-name">' + escapeHtml(b.name) + '</span>' +
        '<span class="book-item-actions">' +
        '<button type="button" class="book-item-btn" data-action="rename" data-id="' + b.id + '" title="Rename" aria-label="Rename book">' + ICONS.edit + '</button>' +
        '<button type="button" class="book-item-btn danger" data-action="delete" data-id="' + b.id + '" title="Delete" aria-label="Delete book">' + ICONS.trash + '</button>' +
        '</span>' +
        '</li>';
    }).join('');

    dom.bookList.querySelectorAll('.book-item').forEach(function (li) {
      li.addEventListener('click', function (e) {
        if (e.target.closest('.book-item-btn')) return;
        selectBook(li.getAttribute('data-id'));
      });
    });
    dom.bookList.querySelectorAll('[data-action="rename"]').forEach(function (btn) {
      btn.addEventListener('click', function (e) { e.stopPropagation(); handleRenameBook(btn.getAttribute('data-id')); });
    });
    dom.bookList.querySelectorAll('[data-action="delete"]').forEach(function (btn) {
      btn.addEventListener('click', function (e) { e.stopPropagation(); handleDeleteBook(btn.getAttribute('data-id')); });
    });
  }

  function selectBook(id) {
    state.activeBookId = id;
    saveActiveBookId(id);
    renderBookList();
    var book = findBook(id);
    if (!book) {
      dom.emptyState.hidden = false;
      dom.entriesContent.hidden = true;
      return;
    }
    dom.emptyState.hidden = true;
    dom.entriesContent.hidden = false;
    dom.activeBookName.textContent = book.name;
    dom.entrySearch.value = '';
    state.search = '';
    state.tagFilter = [];
    renderTagFilterDropdown();
    renderEntryGrid();
  }

  function findEntry(id) {
    return state.vault.entries.filter(function (e) { return e.id === id; })[0];
  }

  function filteredEntries() {
    var list = entriesForBook(state.activeBookId).slice().sort(function (a, b) { return b.updatedAt - a.updatedAt; });
    if (state.tagFilter.length) {
      list = list.filter(function (e) {
        var tags = e.tags || [];
        return state.tagFilter.some(function (t) { return tags.indexOf(t) !== -1; });
      });
    }
    var q = state.search.trim().toLowerCase();
    if (!q) return list;
    return list.filter(function (e) {
      return (e.title || '').toLowerCase().indexOf(q) !== -1 ||
        (e.subtitle || '').toLowerCase().indexOf(q) !== -1 ||
        (e.username || '').toLowerCase().indexOf(q) !== -1;
    });
  }

  function entryDisplayTitle(entry) {
    var title = entry.title || 'Untitled';
    return entry.subtitle ? title + ' (' + entry.subtitle + ')' : title;
  }

  function entryTitleHtml(entry) {
    var titleHtml = escapeHtml(entry.title || 'Untitled');
    return entry.subtitle
      ? titleHtml + ' <span class="entry-subtitle">(' + escapeHtml(entry.subtitle) + ')</span>'
      : titleHtml;
  }

  function entryTagsHtml(entry) {
    var tags = entry.tags || [];
    if (!tags.length) return '';
    return '<div class="entry-tags">' + tags.map(function (t) {
      return '<span class="tag-chip">' + escapeHtml(t) + '</span>';
    }).join('') + '</div>';
  }

  function parseTagsInput(value) {
    var seen = {};
    var out = [];
    (value || '').split(',').forEach(function (raw) {
      var t = raw.trim();
      if (!t || seen[t.toLowerCase()]) return;
      seen[t.toLowerCase()] = true;
      out.push(t);
    });
    return out;
  }

  function collectTagsForActiveBook() {
    var set = {};
    entriesForBook(state.activeBookId).forEach(function (e) {
      (e.tags || []).forEach(function (t) { set[t] = true; });
    });
    return Object.keys(set).sort(function (a, b) { return a.localeCompare(b); });
  }

  function renderTagFilterDropdown() {
    var container = dom.tagFilterDropdown;
    var allTags = collectTagsForActiveBook();
    state.tagFilter = state.tagFilter.filter(function (t) { return allTags.indexOf(t) !== -1; });

    if (!allTags.length) {
      container.hidden = true;
      container.innerHTML = '';
      return;
    }
    container.hidden = false;

    function summaryHtml() {
      return state.tagFilter.length
        ? '<span>' + state.tagFilter.length + ' tag' + (state.tagFilter.length === 1 ? '' : 's') + '</span>'
        : '<span class="dropdown-placeholder">Filter by tag</span>';
    }

    var optionsHtml = allTags.map(function (tag) {
      var active = state.tagFilter.indexOf(tag) !== -1;
      return '<button type="button" class="dropdown-option tag-filter-option' + (active ? ' active' : '') + '" data-tag="' + escapeHtml(tag) + '">' +
        '<span class="tag-filter-check">' + (active ? ICONS.check : '') + '</span>' +
        '<span>' + escapeHtml(tag) + '</span></button>';
    }).join('');

    container.innerHTML =
      '<div class="dropdown">' +
      '<button type="button" class="form-control dropdown-toggle" aria-haspopup="listbox" aria-expanded="false" aria-label="Filter by tag">' +
      '<span class="dropdown-selected">' + summaryHtml() + '</span>' +
      ICONS.chevronDown +
      '</button>' +
      '<div class="dropdown-menu" role="listbox" hidden>' + optionsHtml +
      '<div class="dropdown-divider"></div>' +
      '<button type="button" class="dropdown-option tag-filter-clear" id="btnClearTagFilter"' + (state.tagFilter.length ? '' : ' hidden') + '>Clear filter</button>' +
      '</div></div>';

    var dropdown = container.querySelector('.dropdown');
    var toggle = dropdown.querySelector('.dropdown-toggle');
    var menu = dropdown.querySelector('.dropdown-menu');
    var selectedDisplay = dropdown.querySelector('.dropdown-selected');
    var clearBtn = menu.querySelector('#btnClearTagFilter');

    toggle.addEventListener('click', function (e) {
      e.stopPropagation();
      var isOpen = dropdown.classList.contains('open');
      dropdown.classList.toggle('open', !isOpen);
      menu.hidden = isOpen;
      toggle.setAttribute('aria-expanded', String(!isOpen));
    });

    menu.querySelectorAll('.tag-filter-option').forEach(function (option) {
      option.addEventListener('click', function (e) {
        e.stopPropagation();
        var tag = option.getAttribute('data-tag');
        var idx = state.tagFilter.indexOf(tag);
        var nowActive = idx === -1;
        if (nowActive) state.tagFilter.push(tag); else state.tagFilter.splice(idx, 1);
        option.classList.toggle('active', nowActive);
        option.querySelector('.tag-filter-check').innerHTML = nowActive ? ICONS.check : '';
        selectedDisplay.innerHTML = summaryHtml();
        clearBtn.hidden = state.tagFilter.length === 0;
        renderEntryGrid();
      });
    });

    clearBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      state.tagFilter = [];
      renderTagFilterDropdown();
      renderEntryGrid();
    });
  }

  function renderEntryGrid() {
    var list = filteredEntries();
    dom.entriesCount.textContent = entriesForBook(state.activeBookId).length;
    dom.entriesEmpty.hidden = list.length > 0;
    if (entriesForBook(state.activeBookId).length === 0) {
      dom.entriesEmpty.textContent = 'No passwords saved in this book yet.';
    } else {
      dom.entriesEmpty.textContent = 'No passwords match your search.';
    }

    var isList = state.entryView === 'list';
    dom.entryGrid.innerHTML = isList ? renderEntryTableHtml(list) : list.map(renderEntryCard).join('');

    var openEventName = isList ? 'dblclick' : 'click';
    dom.entryGrid.querySelectorAll(isList ? '.entry-table-row' : '.entry-card').forEach(function (row) {
      if (isList) row.title = 'Double-click to view details';
      row.addEventListener(openEventName, function (e) {
        if (e.target.closest('[data-stop]')) return;
        openEntryModal(findEntry(row.getAttribute('data-id')));
      });
    });
    wireCardIconButtons(dom.entryGrid);
    refreshOtpDisplays();
  }

  function otpRingHtml(entryId) {
    var c = 2 * Math.PI * OTP_RING_RADIUS;
    return '<span class="otp-ring-wrap">' +
      '<svg viewBox="0 0 26 26">' +
      '<circle class="otp-ring-bg" cx="13" cy="13" r="' + OTP_RING_RADIUS + '"></circle>' +
      '<circle class="otp-ring-progress" cx="13" cy="13" r="' + OTP_RING_RADIUS + '" ' +
      'stroke-dasharray="' + c.toFixed(2) + '" stroke-dashoffset="0" data-otp-circle="' + entryId + '"></circle>' +
      '</svg></span>';
  }

  function renderEntryCard(entry) {
    var otpHtml = '';
    if (entry.otpSecret) {
      otpHtml =
        '<div class="entry-row" data-stop>' +
        '<span class="entry-row-label">OTP</span>' +
        '<span class="entry-row-value mono" data-otp-code="' + entry.id + '">------</span>' +
        otpRingHtml(entry.id) +
        '<button type="button" class="entry-icon-btn" data-copy-otp="' + entry.id + '" title="Copy code" aria-label="Copy code">' + ICONS.copy + '</button>' +
        '</div>';
    }
    return '<div class="entry-card" data-id="' + entry.id + '">' +
      '<div class="entry-card-title">' + entryTitleHtml(entry) + '</div>' +
      entryTagsHtml(entry) +
      '<div class="entry-row">' +
      '<span class="entry-row-label">User</span>' +
      '<span class="entry-row-value">' + escapeHtml(entry.username || '—') + '</span>' +
      '<button type="button" class="entry-icon-btn" data-stop data-copy-username="' + entry.id + '" title="Copy username" aria-label="Copy username">' + ICONS.copy + '</button>' +
      '</div>' +
      '<div class="entry-row" data-stop>' +
      '<span class="entry-row-label">Pass</span>' +
      '<span class="entry-row-value masked">••••••••</span>' +
      '<button type="button" class="entry-icon-btn" data-copy-password="' + entry.id + '" title="Copy password" aria-label="Copy password">' + ICONS.copy + '</button>' +
      '</div>' +
      otpHtml +
      '</div>';
  }

  function renderEntryTableHtml(list) {
    return '<table class="entry-table">' +
      '<thead><tr><th>Title</th><th>Username</th><th>Password</th><th>OTP</th></tr></thead>' +
      '<tbody>' + list.map(renderEntryRow).join('') + '</tbody>' +
      '</table>';
  }

  function renderEntryRow(entry) {
    var otpCellHtml = entry.otpSecret
      ? '<td class="entry-table-otp">' +
        '<span class="entry-table-value-inline">' +
        '<button type="button" class="entry-icon-btn" data-stop data-copy-otp="' + entry.id + '" title="Copy code" aria-label="Copy code">' + ICONS.copy + '</button>' +
        otpRingHtml(entry.id) +
        '<span class="entry-row-value mono" data-otp-code="' + entry.id + '">------</span>' +
        '</span></td>'
      : '<td class="entry-table-otp entry-table-empty">—</td>';

    return '<tr class="entry-table-row" data-id="' + entry.id + '">' +
      '<td class="entry-table-title">' +
      '<div class="entry-table-title-line">' + entryTitleHtml(entry) + '</div>' +
      entryTagsHtml(entry) +
      '</td>' +
      '<td><span class="entry-table-value-inline">' +
      '<button type="button" class="entry-icon-btn" data-stop data-copy-username="' + entry.id + '" title="Copy username" aria-label="Copy username">' + ICONS.copy + '</button>' +
      '<span class="entry-row-value">' + escapeHtml(entry.username || '—') + '</span></span></td>' +
      '<td><span class="entry-table-value-inline">' +
      '<button type="button" class="entry-icon-btn" data-stop data-toggle-password="' + entry.id + '" title="Show password" aria-label="Show password">' + ICONS.eye + '</button>' +
      '<button type="button" class="entry-icon-btn" data-stop data-copy-password="' + entry.id + '" title="Copy password" aria-label="Copy password">' + ICONS.copy + '</button>' +
      '<span class="entry-row-value mono" data-pw-text="' + entry.id + '">••••••••</span></span></td>' +
      otpCellHtml +
      '</tr>';
  }

  function wireCardIconButtons(container) {
    container.querySelectorAll('[data-copy-username]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var entry = findEntry(btn.getAttribute('data-copy-username'));
        if (entry) copyToClipboard(entry.username || '', btn);
      });
    });
    container.querySelectorAll('[data-copy-password]').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var entry = findEntry(btn.getAttribute('data-copy-password'));
        if (!entry) return;
        try {
          var plain = await decryptField(state.masterKey, entry.password);
          copyToClipboard(plain, btn);
        } catch (e) {
          openInfoModal('Error', 'Could not decrypt this password.');
        }
      });
    });
    container.querySelectorAll('[data-copy-otp]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var codeEl = container.querySelector('[data-otp-code="' + btn.getAttribute('data-copy-otp') + '"]');
        if (codeEl) copyToClipboard(codeEl.textContent, btn);
      });
    });
    container.querySelectorAll('[data-toggle-password]').forEach(function (btn) {
      var revealed = false;
      btn.addEventListener('click', async function () {
        var entryId = btn.getAttribute('data-toggle-password');
        var textEl = container.querySelector('[data-pw-text="' + entryId + '"]');
        if (!textEl) return;
        if (!revealed) {
          var entry = findEntry(entryId);
          if (!entry) return;
          try {
            var plain = await decryptField(state.masterKey, entry.password);
            textEl.textContent = plain;
            btn.innerHTML = ICONS.eyeOff;
            btn.title = 'Hide password';
            btn.setAttribute('aria-label', 'Hide password');
            revealed = true;
          } catch (e) {
            openInfoModal('Error', 'Could not decrypt this password.');
          }
        } else {
          textEl.textContent = '••••••••';
          btn.innerHTML = ICONS.eye;
          btn.title = 'Show password';
          btn.setAttribute('aria-label', 'Show password');
          revealed = false;
        }
      });
    });
  }

  function startOtpTicker() {
    stopOtpTicker();
    refreshOtpDisplays();
    state.otpTimer = setInterval(refreshOtpDisplays, 1000);
  }

  function stopOtpTicker() {
    if (state.otpTimer) {
      clearInterval(state.otpTimer);
      state.otpTimer = null;
    }
  }

  function ensureOtpSecretCached(entryId) {
    if (state.otpPlainCache[entryId]) return Promise.resolve(state.otpPlainCache[entryId]);
    var entry = findEntry(entryId);
    if (!entry || !entry.otpSecret) return Promise.resolve(null);
    return decryptField(state.masterKey, entry.otpSecret).then(function (plain) {
      state.otpPlainCache[entryId] = plain;
      return plain;
    }).catch(function () { return null; });
  }

  function paintOtp(entryId, code, remaining) {
    document.querySelectorAll('[data-otp-code="' + entryId + '"]').forEach(function (el) { el.textContent = code; });
    var c = 2 * Math.PI * OTP_RING_RADIUS;
    var fraction = remaining / TOTP_PERIOD;
    document.querySelectorAll('[data-otp-circle="' + entryId + '"]').forEach(function (circle) {
      circle.setAttribute('stroke-dasharray', c.toFixed(2));
      circle.setAttribute('stroke-dashoffset', (c * (1 - fraction)).toFixed(2));
      circle.classList.toggle('otp-ring-low', remaining <= 5);
    });
  }

  function refreshOtpDisplays() {
    var codeEls = document.querySelectorAll('[data-otp-code]');
    if (!codeEls.length) return;
    var now = Math.floor(Date.now() / 1000);
    var remaining = totpSecondsRemaining(now);
    var seen = Object.create(null);

    codeEls.forEach(function (el) {
      var entryId = el.getAttribute('data-otp-code');
      if (seen[entryId]) return;
      seen[entryId] = true;
      ensureOtpSecretCached(entryId).then(function (secret) {
        if (!secret) return;
        return totpCode(secret, now).then(function (code) {
          if (code) paintOtp(entryId, code, remaining);
        });
      });
    });
  }

  function openEntryModal(entry) {
    if (entry) renderEntryViewModal(entry);
    else renderEntryEditModal(null);
  }

  function relativeTime(ts) {
    var diff = Math.max(0, Date.now() - ts);
    var mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    var hours = Math.floor(mins / 60);
    if (hours < 24) return hours + 'h ago';
    var days = Math.floor(hours / 24);
    if (days < 7) return days + 'd ago';
    return new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  function renderHistoryListHtml(history) {
    if (!history.length) return '<p class="history-empty">No password changes recorded yet.</p>';
    return history.map(function (h) {
      return '<div class="history-item">' +
        '<span class="history-item-value mono" data-history-text="' + h.id + '">••••••••</span>' +
        '<span class="history-item-time">' + relativeTime(h.changedAt) + '</span>' +
        '<button type="button" class="entry-icon-btn" data-history-toggle="' + h.id + '" title="Show" aria-label="Show password">' + ICONS.eye + '</button>' +
        '<button type="button" class="entry-icon-btn" data-history-copy="' + h.id + '" title="Copy" aria-label="Copy password">' + ICONS.copy + '</button>' +
        '</div>';
    }).join('');
  }

  function wireHistoryReveal(body, entry) {
    var revealed = Object.create(null);
    body.querySelectorAll('[data-history-toggle]').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var id = btn.getAttribute('data-history-toggle');
        var item = (entry.history || []).filter(function (h) { return h.id === id; })[0];
        if (!item) return;
        var textEl = body.querySelector('[data-history-text="' + id + '"]');
        if (!revealed[id]) {
          try {
            var plain = await decryptField(state.masterKey, item.value);
            textEl.textContent = plain;
            btn.innerHTML = ICONS.eyeOff;
            revealed[id] = true;
          } catch (e) {
            openInfoModal('Error', 'Could not decrypt this entry.');
          }
        } else {
          textEl.textContent = '••••••••';
          btn.innerHTML = ICONS.eye;
          revealed[id] = false;
        }
      });
    });
    body.querySelectorAll('[data-history-copy]').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var id = btn.getAttribute('data-history-copy');
        var item = (entry.history || []).filter(function (h) { return h.id === id; })[0];
        if (!item) return;
        try {
          var plain = await decryptField(state.masterKey, item.value);
          copyToClipboard(plain, btn);
        } catch (e) {
          openInfoModal('Error', 'Could not decrypt this entry.');
        }
      });
    });
  }

  function confirmDeleteEntry(entry) {
    openConfirmModal('Delete Password', 'Delete "' + entryDisplayTitle(entry) + '"? This cannot be undone.', 'Delete', function () {
      state.vault.entries = state.vault.entries.filter(function (e) { return e.id !== entry.id; });
      persistVault();
      delete state.otpPlainCache[entry.id];
      renderBookList();
      renderTagFilterDropdown();
      renderEntryGrid();
    }, { danger: true });
  }

  function renderEntryViewModal(entry) {
    var book = findBook(entry.bookId);
    var urlsHtml = entry.urls && entry.urls.length
      ? '<ul class="view-url-list">' + entry.urls.map(function (u) {
          var label = u.label ? escapeHtml(u.label) + ': ' : '';
          return '<li>' + label + '<a href="' + escapeHtml(u.url) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(u.url) + '</a></li>';
        }).join('') + '</ul>'
      : '<p class="history-empty">No URLs added.</p>';

    var otpSectionHtml = '';
    if (entry.otpSecret) {
      otpSectionHtml =
        '<div class="view-section">' +
        '<div class="view-label">One-Time Password</div>' +
        '<div class="view-otp-row">' +
        '<span class="view-otp-code mono" data-otp-code="' + entry.id + '">------</span>' +
        otpRingHtml(entry.id) +
        '<button type="button" class="field-btn" id="btnCopyViewOtp" title="Copy code" aria-label="Copy code">' + ICONS.copy + '</button>' +
        '</div></div>';
    }

    var historyHtml = renderHistoryListHtml(entry.history || []);

    var html =
      '<div class="view-section"><div class="view-label">Book</div><div class="view-value">' + escapeHtml(book ? book.name : '—') + '</div></div>' +
      '<div class="view-section"><div class="view-label">Tags</div>' +
      (entry.tags && entry.tags.length ? entryTagsHtml(entry) : '<div class="view-value"><span class="history-empty">No tags.</span></div>') +
      '</div>' +
      '<div class="view-section"><div class="view-label">Username / Email</div>' +
      '<div class="field-with-btn"><span class="view-value" style="flex:1">' + escapeHtml(entry.username || '—') + '</span>' +
      '<button type="button" class="field-btn" id="btnCopyViewUsername" title="Copy" aria-label="Copy username">' + ICONS.copy + '</button></div></div>' +
      '<div class="view-section"><div class="view-label">Password</div>' +
      '<div class="field-with-btn">' +
      '<span class="view-value mono" id="viewPasswordText" style="flex:1">••••••••</span>' +
      '<button type="button" class="field-btn" id="btnToggleViewPassword" title="Show" aria-label="Show password">' + ICONS.eye + '</button>' +
      '<button type="button" class="field-btn" id="btnCopyViewPassword" title="Copy" aria-label="Copy password">' + ICONS.copy + '</button>' +
      '</div></div>' +
      otpSectionHtml +
      '<div class="view-section"><div class="view-label">URLs</div>' + urlsHtml + '</div>' +
      '<div class="view-section"><div class="view-label">Notes</div><div class="view-value view-notes">' +
      (entry.notes ? escapeHtml(entry.notes) : '<span class="history-empty">No notes.</span>') + '</div></div>' +
      '<div class="view-section"><div class="view-label">Password History</div><div class="history-list">' + historyHtml + '</div></div>' +
      '<div class="modal-actions-between">' +
      '<button type="button" class="btn btn-danger" id="btnDeleteEntry">Delete</button>' +
      '<div class="modal-actions" style="margin:0">' +
      '<button type="button" class="btn btn-ghost" id="btnCloseView">Close</button>' +
      '<button type="button" class="btn btn-primary" id="btnEditEntry">Edit</button>' +
      '</div></div>';

    openModal(entryDisplayTitle(entry), html, function (body) {
      var passRevealed = false;
      body.querySelector('#btnToggleViewPassword').addEventListener('click', async function (e) {
        var btn = e.currentTarget;
        var textEl = body.querySelector('#viewPasswordText');
        if (!passRevealed) {
          try {
            var plain = await decryptField(state.masterKey, entry.password);
            textEl.textContent = plain;
            btn.innerHTML = ICONS.eyeOff;
            btn.title = 'Hide';
            passRevealed = true;
          } catch (err) {
            openInfoModal('Error', 'Could not decrypt this password.');
          }
        } else {
          textEl.textContent = '••••••••';
          btn.innerHTML = ICONS.eye;
          btn.title = 'Show';
          passRevealed = false;
        }
      });
      body.querySelector('#btnCopyViewPassword').addEventListener('click', async function (e) {
        try {
          var plain = await decryptField(state.masterKey, entry.password);
          copyToClipboard(plain, e.currentTarget);
        } catch (err) {
          openInfoModal('Error', 'Could not decrypt this password.');
        }
      });
      body.querySelector('#btnCopyViewUsername').addEventListener('click', function (e) {
        copyToClipboard(entry.username || '', e.currentTarget);
      });
      var copyOtpBtn = body.querySelector('#btnCopyViewOtp');
      if (copyOtpBtn) {
        copyOtpBtn.addEventListener('click', function (e) {
          var codeEl = body.querySelector('[data-otp-code="' + entry.id + '"]');
          if (codeEl) copyToClipboard(codeEl.textContent, e.currentTarget);
        });
      }
      wireHistoryReveal(body, entry);
      body.querySelector('#btnCloseView').addEventListener('click', closeModal);
      body.querySelector('#btnEditEntry').addEventListener('click', function () {
        renderEntryEditModal(entry);
      });
      body.querySelector('#btnDeleteEntry').addEventListener('click', function () {
        closeModal();
        confirmDeleteEntry(entry);
      });
      refreshOtpDisplays();
    }, { wide: true });
  }

  function renderUrlRowHtml(u) {
    return '<div class="url-row" data-url-id="' + u.id + '">' +
      '<input type="text" class="form-control url-row-label" data-url-label placeholder="Label" value="' + escapeHtml(u.label || '') + '">' +
      '<input type="text" class="form-control url-row-value" data-url-value placeholder="https://..." value="' + escapeHtml(u.url || '') + '">' +
      '<button type="button" class="field-btn" data-remove-url title="Remove" aria-label="Remove URL">' + ICONS.x + '</button>' +
      '</div>';
  }

  async function renderEntryEditModal(entry) {
    var isNew = !entry;
    var plainPassword = '';
    var plainOtp = '';
    if (entry) {
      try { plainPassword = await decryptField(state.masterKey, entry.password); } catch (e) { plainPassword = ''; }
      if (entry.otpSecret) {
        try { plainOtp = await decryptField(state.masterKey, entry.otpSecret); } catch (e) { plainOtp = ''; }
      }
    }

    var books = booksSorted();
    var formState = { bookId: entry ? entry.bookId : state.activeBookId };

    var urls = entry && entry.urls && entry.urls.length ? entry.urls : [{ id: generateId(), label: '', url: '' }];

    var html =
      '<div class="form-group"><label>Book</label><div id="fieldBookDropdown"></div></div>' +
      '<div class="form-row">' +
      '<div class="form-group"><label for="fieldTitle">Title</label>' +
      '<input type="text" id="fieldTitle" class="form-control" placeholder="e.g. Amazon" value="' + escapeHtml(entry ? entry.title : '') + '"></div>' +
      '<div class="form-group"><label for="fieldSubtitle">Subtitle (optional)</label>' +
      '<input type="text" id="fieldSubtitle" class="form-control" placeholder="e.g. US" value="' + escapeHtml(entry ? (entry.subtitle || '') : '') + '"></div>' +
      '</div>' +
      '<div class="form-group"><label for="fieldUsername">Username / Email</label>' +
      '<input type="text" id="fieldUsername" class="form-control" value="' + escapeHtml(entry ? entry.username : '') + '"></div>' +
      '<div class="form-group"><label for="fieldPassword">Password</label>' +
      '<div class="field-with-btn"><input type="password" id="fieldPassword" class="form-control" value="' + escapeHtml(plainPassword) + '">' +
      '<button type="button" class="field-btn" id="btnToggleFieldPassword" title="Show" aria-label="Show password">' + ICONS.eye + '</button></div></div>' +
      '<div class="form-group"><label for="fieldOtp">TOTP secret (optional, base32)</label>' +
      '<input type="text" id="fieldOtp" class="form-control mono" placeholder="e.g. JBSWY3DPEHPK3PXP" value="' + escapeHtml(plainOtp) + '"></div>' +
      '<div class="form-group"><label>URLs</label><div class="url-rows" id="urlRows">' +
      urls.map(renderUrlRowHtml).join('') +
      '</div><button type="button" class="btn btn-ghost btn-add-row" id="btnAddUrlRow">' + ICONS.plus + ' Add URL</button></div>' +
      '<div class="form-group"><label for="fieldTags">Tags</label>' +
      '<input type="text" id="fieldTags" class="form-control" placeholder="Comma separated, e.g. Work, Shared" value="' +
      escapeHtml(entry && entry.tags ? entry.tags.join(', ') : '') + '"></div>' +
      '<div class="form-group"><label for="fieldNotes">Notes</label>' +
      '<textarea id="fieldNotes" class="form-control" rows="3">' + escapeHtml(entry ? entry.notes : '') + '</textarea></div>' +
      '<div class="modal-actions-between">' +
      (isNew ? '<span></span>' : '<button type="button" class="btn btn-danger" id="btnDeleteEntryEdit">Delete</button>') +
      '<div class="modal-actions" style="margin:0">' +
      '<button type="button" class="btn btn-ghost" id="btnCancelEdit">Cancel</button>' +
      '<button type="button" class="btn btn-primary" id="btnSaveEntry">Save</button>' +
      '</div></div>';

    openModal(isNew ? 'New Password' : 'Edit Password', html, function (body) {
      renderDropdown(body.querySelector('#fieldBookDropdown'), {
        items: books.map(function (b) { return { value: b.id, label: b.name }; }),
        value: formState.bookId,
        ariaLabel: 'Book',
        onChange: function (value) { formState.bookId = value; }
      });
      wireEditModal(body, entry, plainPassword, formState);
    }, { wide: true });
  }

  function wireEditModal(body, entry, originalPassword, formState) {
    var pwInput = body.querySelector('#fieldPassword');
    var toggleBtn = body.querySelector('#btnToggleFieldPassword');
    var pwVisible = false;
    toggleBtn.addEventListener('click', function () {
      pwVisible = !pwVisible;
      pwInput.type = pwVisible ? 'text' : 'password';
      toggleBtn.innerHTML = pwVisible ? ICONS.eyeOff : ICONS.eye;
    });

    var urlRows = body.querySelector('#urlRows');
    function wireRemoveButtons() {
      urlRows.querySelectorAll('[data-remove-url]').forEach(function (btn) {
        btn.onclick = function () {
          if (urlRows.querySelectorAll('.url-row').length <= 1) {
            var row = btn.closest('.url-row');
            row.querySelector('[data-url-label]').value = '';
            row.querySelector('[data-url-value]').value = '';
            return;
          }
          btn.closest('.url-row').remove();
        };
      });
    }
    wireRemoveButtons();

    body.querySelector('#btnAddUrlRow').addEventListener('click', function () {
      var wrapper = document.createElement('div');
      wrapper.innerHTML = renderUrlRowHtml({ id: generateId(), label: '', url: '' });
      urlRows.appendChild(wrapper.firstChild);
      wireRemoveButtons();
    });

    body.querySelector('#btnCancelEdit').addEventListener('click', function () {
      if (entry) renderEntryViewModal(entry);
      else closeModal();
    });

    var deleteBtn = body.querySelector('#btnDeleteEntryEdit');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', function () {
        closeModal();
        confirmDeleteEntry(entry);
      });
    }

    body.querySelector('#btnSaveEntry').addEventListener('click', function () {
      saveEntryFromForm(body, entry, originalPassword, formState);
    });
  }

  async function saveEntryFromForm(body, entry, originalPassword, formState) {
    var bookId = formState.bookId;
    var title = body.querySelector('#fieldTitle').value.trim();
    var subtitle = body.querySelector('#fieldSubtitle').value.trim();
    var username = body.querySelector('#fieldUsername').value.trim();
    var plainPassword = body.querySelector('#fieldPassword').value;
    var plainOtp = body.querySelector('#fieldOtp').value.trim();
    var notes = body.querySelector('#fieldNotes').value;
    var tags = parseTagsInput(body.querySelector('#fieldTags').value);

    if (!title) {
      openInfoModal('Missing Title', 'Please give this password entry a title.');
      return;
    }

    var urls = [];
    body.querySelectorAll('.url-row').forEach(function (row) {
      var label = row.querySelector('[data-url-label]').value.trim();
      var url = row.querySelector('[data-url-value]').value.trim();
      if (url) urls.push({ id: row.getAttribute('data-url-id') || generateId(), label: label, url: url });
    });

    var saveBtn = body.querySelector('#btnSaveEntry');
    saveBtn.disabled = true;
    try {
      var encPassword = await encryptField(state.masterKey, plainPassword);
      var encOtp = plainOtp ? await encryptField(state.masterKey, plainOtp) : null;
      var now = Date.now();

      if (entry) {
        var history = entry.history ? entry.history.slice() : [];
        if (plainPassword !== originalPassword) {
          history.unshift({ id: generateId(), value: entry.password, changedAt: now });
          if (history.length > 20) history = history.slice(0, 20);
        }
        entry.bookId = bookId;
        entry.title = title;
        entry.subtitle = subtitle;
        entry.username = username;
        entry.password = encPassword;
        entry.otpSecret = encOtp;
        entry.urls = urls;
        entry.notes = notes;
        entry.tags = tags;
        entry.history = history;
        entry.updatedAt = now;
        delete state.otpPlainCache[entry.id];
      } else {
        entry = {
          id: generateId(), bookId: bookId, title: title, subtitle: subtitle, username: username,
          password: encPassword, otpSecret: encOtp, urls: urls, notes: notes, tags: tags,
          history: [], createdAt: now, updatedAt: now
        };
        state.vault.entries.push(entry);
      }

      persistVault();
      closeModal();
      renderBookList();
      if (state.activeBookId !== bookId) {
        selectBook(bookId);
      } else {
        renderTagFilterDropdown();
        renderEntryGrid();
      }
    } catch (e) {
      openInfoModal('Error', 'Could not save this password. Please try again.');
      saveBtn.disabled = false;
    }
  }

  function downloadFile(filename, content, mime) {
    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function exportAllData() {
    var kdf = loadKdf();
    if (!kdf) return;
    if (state.vault.books.length === 0) {
      openInfoModal('Export Passwords', 'There are no books to export yet.');
      return;
    }
    openExportBookSelectModal(function (selectedBookIds, encryptPasswords) {
      openExportWarningModal(encryptPasswords, async function () {
        var books = state.vault.books.filter(function (b) { return selectedBookIds.indexOf(b.id) !== -1; });
        var entries = state.vault.entries.filter(function (e) { return selectedBookIds.indexOf(e.bookId) !== -1; });

        if (encryptPasswords) {
          var payload = {
            version: 1,
            encrypted: true,
            salt: kdf.salt,
            iterations: kdf.iterations,
            verifier: kdf.verifier,
            books: books,
            entries: entries
          };
          downloadFile('passwordbuddy-export.json', JSON.stringify(payload, null, 2), 'application/json');
          return;
        }

        try {
          var plainEntries = await decryptEntriesForExport(entries);
          var plainPayload = { version: 1, encrypted: false, books: books, entries: plainEntries };
          downloadFile('passwordbuddy-export.json', JSON.stringify(plainPayload, null, 2), 'application/json');
        } catch (e) {
          openInfoModal('Error', 'Could not decrypt passwords for export.');
        }
      });
    });
  }

  async function decryptEntriesForExport(entries) {
    var out = [];
    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      var plainHistory = [];
      var srcHistory = entry.history || [];
      for (var j = 0; j < srcHistory.length; j++) {
        var h = srcHistory[j];
        plainHistory.push({ id: h.id, value: await decryptField(state.masterKey, h.value), changedAt: h.changedAt });
      }
      out.push({
        id: entry.id,
        bookId: entry.bookId,
        title: entry.title,
        subtitle: entry.subtitle,
        tags: entry.tags,
        username: entry.username,
        password: await decryptField(state.masterKey, entry.password),
        otpSecret: entry.otpSecret ? await decryptField(state.masterKey, entry.otpSecret) : null,
        urls: entry.urls,
        notes: entry.notes,
        history: plainHistory,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      });
    }
    return out;
  }

  function openExportBookSelectModal(onConfirm) {
    var books = booksSorted();
    var rowsHtml = books.map(function (b) {
      var count = entriesForBook(b.id).length;
      return '<label class="export-book-row selected">' +
        '<input type="checkbox" class="export-book-checkbox" data-book="' + b.id + '" checked>' +
        '<span class="export-book-row-name">' + escapeHtml(b.name) + '</span>' +
        '<span class="export-book-row-meta">' + count + ' password' + (count === 1 ? '' : 's') + '</span>' +
        '</label>';
    }).join('');

    var html =
      '<form id="exportBookForm">' +
      '<div class="form-group">' +
      '<label>Books to include</label>' +
      '<div class="export-book-list">' + rowsHtml + '</div>' +
      '<button type="button" class="btn btn-ghost btn-sm" id="btnToggleAllExportBooks" style="margin-top:8px;">Select / Deselect All</button>' +
      '<div class="form-error" id="exportBookError">Select at least one book to export.</div>' +
      '</div>' +
      '<div class="form-group">' +
      '<label class="form-check">' +
      '<span class="checkbox-custom export-encrypt-check">' +
      '<input type="checkbox" id="exportEncryptPasswords" checked>' +
      '<span class="checkbox-box">' + ICONS.check + '</span>' +
      '</span>' +
      'Encrypt passwords in the exported file' +
      '</label>' +
      '</div>' +
      '<div class="modal-actions">' +
      '<button type="button" class="btn btn-ghost" id="btnCancelExportBooks">Cancel</button>' +
      '<button type="submit" class="btn btn-primary">Next</button>' +
      '</div>' +
      '</form>';

    openModal('Export Passwords', html, function (body) {
      var checkboxes = body.querySelectorAll('.export-book-checkbox');

      checkboxes.forEach(function (cb) {
        cb.addEventListener('change', function () {
          cb.closest('.export-book-row').classList.toggle('selected', cb.checked);
        });
      });

      body.querySelector('#btnToggleAllExportBooks').addEventListener('click', function () {
        var allChecked = Array.prototype.every.call(checkboxes, function (cb) { return cb.checked; });
        checkboxes.forEach(function (cb) {
          cb.checked = !allChecked;
          cb.closest('.export-book-row').classList.toggle('selected', cb.checked);
        });
      });

      body.querySelector('#btnCancelExportBooks').addEventListener('click', closeModal);

      body.querySelector('#exportBookForm').addEventListener('submit', function (e) {
        e.preventDefault();
        var selectedIds = Array.prototype.filter.call(checkboxes, function (cb) { return cb.checked; })
          .map(function (cb) { return cb.getAttribute('data-book'); });

        var errorEl = body.querySelector('#exportBookError');
        if (selectedIds.length === 0) {
          errorEl.classList.add('visible');
          return;
        }
        errorEl.classList.remove('visible');
        var encryptPasswords = body.querySelector('#exportEncryptPasswords').checked;
        closeModal();
        onConfirm(selectedIds, encryptPasswords);
      });
    });
  }

  function openExportWarningModal(encryptPasswords, onConfirm) {
    var warningText = encryptPasswords
      ? 'The export is plain JSON. Titles, usernames, and notes are readable by anyone — only passwords, OTP secrets, and history are encrypted.'
      : 'The export is plain JSON with encryption off — everything, including passwords, will be fully readable by anyone who opens it.';
    var html =
      '<p class="auth-warning">' + ICONS.alertTriangle + warningText +
      '</p>' +
      '<div class="modal-actions">' +
      '<button type="button" class="btn btn-ghost" id="btnExportCancel">Cancel</button>' +
      '<button type="button" class="btn btn-primary" id="btnExportConfirm">Export</button>' +
      '</div>';
    openModal('Export Passwords', html, function (body) {
      body.querySelector('#btnExportCancel').addEventListener('click', closeModal);
      body.querySelector('#btnExportConfirm').addEventListener('click', function () {
        closeModal();
        onConfirm();
      });
    }, { autoSize: true });
  }

  function showImportError() {
    openInfoModal('Import Failed', 'Could not import that file. Make sure it is a Password Buddy JSON export.');
  }

  function openMasterKeyPromptModal(onSubmit) {
    var html =
      '<p class="modal-message">Enter the master key that was used to encrypt this backup file.</p>' +
      '<div class="form-group"><label for="importPasswordInput">Master key</label>' +
      '<input type="password" id="importPasswordInput" class="form-control" autocomplete="current-password"></div>' +
      '<p class="auth-error" id="importPasswordError" hidden></p>' +
      '<div class="modal-actions">' +
      '<button class="btn btn-ghost" id="btnImportPwCancel">Cancel</button>' +
      '<button class="btn btn-primary" id="btnImportPwSubmit">Continue</button>' +
      '</div>';
    openModal('Import Backup', html, function (body) {
      var input = body.querySelector('#importPasswordInput');
      var errorEl = body.querySelector('#importPasswordError');
      input.focus();
      body.querySelector('#btnImportPwCancel').addEventListener('click', closeModal);
      function submit() {
        errorEl.hidden = true;
        onSubmit(input.value, function (msg) {
          errorEl.textContent = msg;
          errorEl.hidden = false;
        });
      }
      input.addEventListener('keydown', function (e) { if (e.key === 'Enter') submit(); });
      body.querySelector('#btnImportPwSubmit').addEventListener('click', submit);
    }, { autoSize: true });
  }

  function importDataFromFile(file) {
    var reader = new FileReader();
    reader.onload = function () {
      var data;
      try { data = JSON.parse(reader.result); } catch (e) { showImportError(); return; }
      if (!data || !Array.isArray(data.books) || !Array.isArray(data.entries)) {
        showImportError();
        return;
      }
      if (data.encrypted === false) {
        handleImportPlaintext(data);
        return;
      }
      if (!data.salt || !data.iterations || !data.verifier) {
        showImportError();
        return;
      }
      openMasterKeyPromptModal(function (password, showErr) {
        handleImportWithPassword(data, password, showErr);
      });
    };
    reader.readAsText(file);
  }

  async function handleImportPlaintext(data) {
    try {
      var idMap = {};
      var newBooks = booksFromPlainPayload(data, idMap);
      var newEntries = await encryptPlainEntries(data.entries, idMap, newBooks);

      if (state.vault.books.length > 0 || state.vault.entries.length > 0) {
        openImportConflictModal(
          newBooks, newEntries,
          function () { applyImportedData(newBooks, newEntries, true); },
          function () { applyImportedData(newBooks, newEntries, false); }
        );
      } else {
        applyImportedData(newBooks, newEntries, false);
      }
    } catch (e) {
      showImportError();
    }
  }

  function booksFromPlainPayload(data, idMap) {
    return data.books.map(function (b) {
      var nb = { id: generateId(), name: String(b.name || 'Untitled'), createdAt: b.createdAt || Date.now() };
      if (b.id) idMap[b.id] = nb.id;
      return nb;
    });
  }

  async function encryptPlainEntries(entries, idMap, newBooks) {
    var newEntries = [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];

      var newHistory = [];
      var srcHistory = Array.isArray(e.history) ? e.history : [];
      for (var j = 0; j < srcHistory.length; j++) {
        var h = srcHistory[j];
        newHistory.push({
          id: generateId(),
          value: await encryptField(state.masterKey, String(h.value || '')),
          changedAt: h.changedAt || Date.now()
        });
      }

      newEntries.push({
        id: generateId(),
        bookId: idMap[e.bookId] || (newBooks[0] ? newBooks[0].id : null),
        title: String(e.title || ''),
        subtitle: String(e.subtitle || ''),
        tags: Array.isArray(e.tags) ? e.tags.map(String) : [],
        username: String(e.username || ''),
        password: await encryptField(state.masterKey, String(e.password || '')),
        otpSecret: e.otpSecret ? await encryptField(state.masterKey, String(e.otpSecret)) : null,
        urls: Array.isArray(e.urls) ? e.urls.map(function (u) { return { id: generateId(), label: String(u.label || ''), url: String(u.url || '') }; }) : [],
        notes: String(e.notes || ''),
        history: newHistory,
        createdAt: e.createdAt || Date.now(),
        updatedAt: e.updatedAt || Date.now()
      });
    }
    return newEntries;
  }

  async function handleImportWithPassword(data, password, showErr) {
    try {
      var salt = b64ToBytes(data.salt);
      var fileKey = await deriveKey(password, salt, data.iterations);
      var ok = await checkVerifier(fileKey, data.verifier);
      if (!ok) { showErr('Incorrect master key for this file.'); return; }

      var idMap = {};
      var newBooks = data.books.map(function (b) {
        var nb = { id: generateId(), name: String(b.name || 'Untitled'), createdAt: b.createdAt || Date.now() };
        if (b.id) idMap[b.id] = nb.id;
        return nb;
      });

      var newEntries = [];
      for (var i = 0; i < data.entries.length; i++) {
        var e = data.entries[i];

        var plainPassword = '';
        try { plainPassword = await decryptField(fileKey, e.password); } catch (err) { plainPassword = ''; }

        var plainOtp = null;
        if (e.otpSecret) {
          try { plainOtp = await decryptField(fileKey, e.otpSecret); } catch (err) { plainOtp = null; }
        }

        var newHistory = [];
        var srcHistory = Array.isArray(e.history) ? e.history : [];
        for (var j = 0; j < srcHistory.length; j++) {
          var h = srcHistory[j];
          var plainHist;
          try { plainHist = await decryptField(fileKey, h.value); } catch (err) { continue; }
          newHistory.push({ id: generateId(), value: await encryptField(state.masterKey, plainHist), changedAt: h.changedAt || Date.now() });
        }

        newEntries.push({
          id: generateId(),
          bookId: idMap[e.bookId] || (newBooks[0] ? newBooks[0].id : null),
          title: String(e.title || ''),
          subtitle: String(e.subtitle || ''),
          tags: Array.isArray(e.tags) ? e.tags.map(String) : [],
          username: String(e.username || ''),
          password: await encryptField(state.masterKey, plainPassword),
          otpSecret: plainOtp ? await encryptField(state.masterKey, plainOtp) : null,
          urls: Array.isArray(e.urls) ? e.urls.map(function (u) { return { id: generateId(), label: String(u.label || ''), url: String(u.url || '') }; }) : [],
          notes: String(e.notes || ''),
          history: newHistory,
          createdAt: e.createdAt || Date.now(),
          updatedAt: e.updatedAt || Date.now()
        });
      }

      closeModal();

      if (state.vault.books.length > 0 || state.vault.entries.length > 0) {
        openImportConflictModal(
          newBooks, newEntries,
          function () { applyImportedData(newBooks, newEntries, true); },
          function () { applyImportedData(newBooks, newEntries, false); }
        );
      } else {
        applyImportedData(newBooks, newEntries, false);
      }
    } catch (e) {
      showErr('Could not read this backup file.');
    }
  }

  function applyImportedData(newBooks, newEntries, replaceExisting) {
    if (replaceExisting) {
      state.vault.books = newBooks;
      state.vault.entries = newEntries;
    } else {
      state.vault.books = state.vault.books.concat(newBooks);
      state.vault.entries = state.vault.entries.concat(newEntries);
    }
    persistVault();
    if (!state.activeBookId || !findBook(state.activeBookId)) {
      state.activeBookId = state.vault.books.length ? state.vault.books[0].id : null;
      saveActiveBookId(state.activeBookId);
    }
    renderBookList();
    selectBook(state.activeBookId);
  }

  function handleLoadSample(e) {
    e.preventDefault();
    if (window.location.protocol === 'file:') {
      openInfoModal(
        'Server Required',
        'Loading sample data needs the app to be served from a local or remote server — it can\'t read local files when index.html is opened directly from your file system. Instead, download passwordBuddy_sample.json from cdnBuddy/samples and use the Import button (top-left) to load it.'
      );
      return;
    }
    fetch('https://isafuianish-dev.github.io/webapp_cdnBuddy/samples/passwordBuddy_sample.json')
      .then(function (res) {
        if (!res.ok) throw new Error('Request failed');
        return res.json();
      })
      .then(function (parsed) {
        if (!parsed || !Array.isArray(parsed.books) || !Array.isArray(parsed.entries)) throw new Error('Invalid data');
        return applySamplePayload(parsed);
      })
      .catch(function () {
        openInfoModal('Load Failed', 'Could not load the sample data.');
      });
  }

  async function applySamplePayload(data) {
    var idMap = {};
    var newBooks = booksFromPlainPayload(data, idMap);
    var newEntries = await encryptPlainEntries(data.entries, idMap, newBooks);
    applyImportedData(newBooks, newEntries, false);
  }

  function openImportConflictModal(importedBooks, importedEntries, onReplace, onAppend) {
    var existingBookCount = state.vault.books.length;
    var existingEntryCount = state.vault.entries.length;
    var html =
      '<p class="modal-message">This browser already has ' + existingBookCount + ' book' + (existingBookCount === 1 ? '' : 's') +
      ' (' + existingEntryCount + ' password' + (existingEntryCount === 1 ? '' : 's') + ') saved. The file you picked has ' +
      importedBooks.length + ' book' + (importedBooks.length === 1 ? '' : 's') +
      ' (' + importedEntries.length + ' password' + (importedEntries.length === 1 ? '' : 's') + '). What would you like to do?</p>' +
      '<div class="modal-actions">' +
      '<button class="btn btn-ghost" id="btnImportCancel">Cancel</button>' +
      '<button class="btn btn-danger" id="btnImportReplace">Replace All</button>' +
      '<button class="btn btn-primary" id="btnImportAppend">Append</button>' +
      '</div>';
    openModal('Import Data', html, function (body) {
      body.querySelector('#btnImportCancel').addEventListener('click', closeModal);
      body.querySelector('#btnImportReplace').addEventListener('click', function () { closeModal(); onReplace(); });
      body.querySelector('#btnImportAppend').addEventListener('click', function () { closeModal(); onAppend(); });
    }, { autoSize: true });
  }

  function openSettingsModal() {
    Buddy.settings.open(APP_KEY, openModal, closeModal, { appVersion: APP_VERSION });
  }

  function openChangeMasterKeyModal() {
    var html =
      '<div class="form-group"><label for="currentMasterKeyInput">Current master key</label>' +
      '<input type="password" id="currentMasterKeyInput" class="form-control" autocomplete="current-password"></div>' +
      '<div class="form-group"><label for="newMasterKeyInput">New master key</label>' +
      '<input type="password" id="newMasterKeyInput" class="form-control" autocomplete="new-password"></div>' +
      '<div class="form-group"><label for="newMasterKeyConfirmInput">Confirm new master key</label>' +
      '<input type="password" id="newMasterKeyConfirmInput" class="form-control" autocomplete="new-password"></div>' +
      '<p class="auth-error" id="changeMasterKeyError" hidden></p>' +
      '<div class="modal-actions">' +
      '<button type="button" class="btn btn-ghost" id="btnCancelChangeMasterKey">Cancel</button>' +
      '<button type="button" class="btn btn-primary" id="btnChangeMasterKey">Update Master Key</button>' +
      '</div>';

    openModal('Change Master Key', html, function (body) {
      body.querySelector('#btnCancelChangeMasterKey').addEventListener('click', closeModal);
      body.querySelector('#btnChangeMasterKey').addEventListener('click', function () {
        handleChangeMasterKey(body);
      });
    }, { autoSize: true });
  }

  async function handleChangeMasterKey(body) {
    var currentPw = body.querySelector('#currentMasterKeyInput').value;
    var newPw = body.querySelector('#newMasterKeyInput').value;
    var newPwConfirm = body.querySelector('#newMasterKeyConfirmInput').value;
    var errorEl = body.querySelector('#changeMasterKeyError');
    errorEl.hidden = true;

    if (newPw.length < 8) { errorEl.textContent = 'New master key must be at least 8 characters.'; errorEl.hidden = false; return; }
    if (newPw !== newPwConfirm) { errorEl.textContent = 'New master keys do not match.'; errorEl.hidden = false; return; }

    var kdf = loadKdf();
    if (!kdf) { errorEl.textContent = 'Could not read your vault settings.'; errorEl.hidden = false; return; }

    var btn = body.querySelector('#btnChangeMasterKey');
    btn.disabled = true;
    try {
      var currentSalt = b64ToBytes(kdf.salt);
      var currentKeyCheck = await deriveKey(currentPw, currentSalt, kdf.iterations);
      var ok = await checkVerifier(currentKeyCheck, kdf.verifier);
      if (!ok) {
        errorEl.textContent = 'Current master key is incorrect.';
        errorEl.hidden = false;
        return;
      }

      var newSalt = randomBytes(16);
      var newKey = await deriveKey(newPw, newSalt, PBKDF2_ITERATIONS);

      for (var i = 0; i < state.vault.entries.length; i++) {
        var e = state.vault.entries[i];
        var plainPw = await decryptField(state.masterKey, e.password);
        e.password = await encryptField(newKey, plainPw);
        if (e.otpSecret) {
          var plainOtp = await decryptField(state.masterKey, e.otpSecret);
          e.otpSecret = await encryptField(newKey, plainOtp);
        }
        for (var j = 0; j < (e.history || []).length; j++) {
          var h = e.history[j];
          var plainHist = await decryptField(state.masterKey, h.value);
          h.value = await encryptField(newKey, plainHist);
        }
      }

      var newVerifier = await makeVerifier(newKey);
      saveKdf({ salt: bytesToB64(newSalt), iterations: PBKDF2_ITERATIONS, verifier: newVerifier });
      persistVault();

      state.masterKey = newKey;
      state.otpPlainCache = Object.create(null);

      openInfoModal('Master Key Updated', 'Your master key has been changed and all saved passwords were re-encrypted.');
    } catch (e) {
      errorEl.textContent = 'Could not update your master key. Please try again.';
      errorEl.hidden = false;
    } finally {
      btn.disabled = false;
    }
  }

  function renderDropdown(container, config) {
    var items = config.items || [];
    var selectedItem = items.filter(function (i) { return i.value === config.value; })[0];

    var selectedHtml = selectedItem
      ? (selectedItem.icon || '') + '<span>' + escapeHtml(selectedItem.label) + '</span>'
      : '<span class="dropdown-placeholder">' + escapeHtml(config.placeholder || 'Select') + '</span>';

    var optionsHtml = items.map(function (item) {
      var activeClass = item.value === config.value ? ' active' : '';
      return '<button type="button" class="dropdown-option' + activeClass + '" data-value="' + escapeHtml(item.value) + '">' +
        (item.icon || '') + '<span>' + escapeHtml(item.label) + '</span></button>';
    }).join('');

    container.innerHTML =
      '<div class="dropdown">' +
      '<button type="button" class="form-control dropdown-toggle" aria-haspopup="listbox" aria-expanded="false"' +
      (config.ariaLabel ? ' aria-label="' + escapeHtml(config.ariaLabel) + '"' : '') + '>' +
      '<span class="dropdown-selected">' + selectedHtml + '</span>' +
      ICONS.chevronDown +
      '</button>' +
      '<div class="dropdown-menu" role="listbox" hidden>' + optionsHtml + '</div>' +
      '</div>';

    var dropdown = container.querySelector('.dropdown');
    var toggle = dropdown.querySelector('.dropdown-toggle');
    var menu = dropdown.querySelector('.dropdown-menu');
    var selectedDisplay = dropdown.querySelector('.dropdown-selected');

    toggle.addEventListener('click', function (e) {
      e.stopPropagation();
      var isOpen = dropdown.classList.contains('open');
      if (isOpen) {
        dropdown.classList.remove('open');
        menu.hidden = true;
        toggle.setAttribute('aria-expanded', 'false');
      } else {
        dropdown.classList.add('open');
        menu.hidden = false;
        toggle.setAttribute('aria-expanded', 'true');
      }
    });

    menu.querySelectorAll('.dropdown-option').forEach(function (option) {
      option.addEventListener('click', function () {
        var value = option.getAttribute('data-value');
        var item = items.filter(function (i) { return i.value === value; })[0];
        config.value = value;
        selectedDisplay.innerHTML = item ? (item.icon || '') + '<span>' + escapeHtml(item.label) + '</span>' : '';
        menu.querySelectorAll('.dropdown-option').forEach(function (o) {
          o.classList.toggle('active', o === option);
        });
        dropdown.classList.remove('open');
        menu.hidden = true;
        toggle.setAttribute('aria-expanded', 'false');
        if (typeof config.onChange === 'function') config.onChange(value);
      });
    });
  }

  function copyToClipboard(text, btn) {
    function showCopied() {
      if (!btn) return;
      var original = btn.innerHTML;
      btn.classList.add('copied');
      btn.innerHTML = ICONS.check;
      setTimeout(function () {
        btn.classList.remove('copied');
        btn.innerHTML = original;
      }, 1200);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(showCopied, function () { fallbackCopy(text, showCopied); });
    } else {
      fallbackCopy(text, showCopied);
    }
  }

  function fallbackCopy(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
    done();
  }

  function openPromptModal(title, label, initialValue, onSubmit) {
    var html =
      '<div class="form-group"><label for="promptInput">' + escapeHtml(label) + '</label>' +
      '<input type="text" id="promptInput" class="form-control" value="' + escapeHtml(initialValue) + '"></div>' +
      '<div class="modal-actions">' +
      '<button class="btn btn-ghost" id="btnPromptCancel">Cancel</button>' +
      '<button class="btn btn-primary" id="btnPromptSave">Save</button>' +
      '</div>';
    openModal(title, html, function (body) {
      var input = body.querySelector('#promptInput');
      input.focus();
      input.select();
      function submit() {
        var val = input.value;
        closeModal();
        onSubmit(val);
      }
      input.addEventListener('keydown', function (e) { if (e.key === 'Enter') submit(); });
      body.querySelector('#btnPromptCancel').addEventListener('click', closeModal);
      body.querySelector('#btnPromptSave').addEventListener('click', submit);
    }, { autoSize: true });
  }

  function openConfirmModal(title, message, confirmLabel, onConfirm, opts) {
    opts = opts || {};
    var danger = opts.danger ? 'btn-danger' : 'btn-primary';
    var html =
      '<p class="modal-message">' + escapeHtml(message) + '</p>' +
      '<div class="modal-actions">' +
      '<button class="btn btn-ghost" id="btnConfirmNo">Cancel</button>' +
      '<button class="btn ' + danger + '" id="btnConfirmYes">' + escapeHtml(confirmLabel) + '</button>' +
      '</div>';
    openModal(title, html, function (body) {
      body.querySelector('#btnConfirmNo').addEventListener('click', closeModal);
      body.querySelector('#btnConfirmYes').addEventListener('click', function () {
        closeModal();
        onConfirm();
      });
    }, { autoSize: true });
  }

  function openInfoModal(title, message) {
    var html = '<p class="modal-message">' + escapeHtml(message) + '</p>' +
      '<div class="modal-actions"><button class="btn btn-primary" id="btnInfoOk">OK</button></div>';
    openModal(title, html, function (body) {
      body.querySelector('#btnInfoOk').addEventListener('click', closeModal);
    }, { autoSize: true });
  }
})();
