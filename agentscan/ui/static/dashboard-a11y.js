/* Accessible drawer, toast, and navigation state helpers (issue #40). */
(function (root) {
  'use strict';

  const FOCUSABLE = [
    'a[href]',
    'area[href]',
    'button:not([disabled])',
    'input:not([disabled]):not([type="hidden"])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    'iframe',
    'object',
    'embed',
    'summary',
    '[contenteditable="true"]',
    '[tabindex]:not([tabindex="-1"])'
  ].join(',');

  const TOAST_VISIBLE_CLASSES = ['translate-y-12', 'opacity-0', 'pointer-events-none'];

  const isElement = value => Boolean(value) && typeof value === 'object' &&
    typeof value.getAttribute === 'function' && typeof value.setAttribute === 'function';

  function focusableWithin(element) {
    if (!isElement(element) || typeof element.querySelectorAll !== 'function') return [];
    return Array.from(element.querySelectorAll(FOCUSABLE)).filter(item => {
      if (!isElement(item)) return false;
      if (item.hidden === true) return false;
      if (item.getAttribute('aria-hidden') === 'true') return false;
      if (item.getAttribute('disabled') !== null) return false;
      if (item.getAttribute('tabindex') === '-1') return false;
      return true;
    });
  }

  function createDrawerController(options) {
    const opts = options || {};
    const doc = opts.document || root.document;
    if (!doc) throw new Error('AgentScanA11y.createDrawerController requires a document');
    const drawer = opts.drawer || doc.getElementById('sidebar');
    if (!drawer) throw new Error('AgentScanA11y.createDrawerController could not find the drawer');
    const toggle = opts.toggle || doc.getElementById('btn-mobile-menu');
    const backdrop = opts.backdrop || doc.getElementById('sidebar-backdrop');
    let openState = Boolean(drawer.classList && drawer.classList.contains('mobile-open'));
    let opener = null;
    let listening = false;

    function setExpanded(value) {
      if (toggle && typeof toggle.setAttribute === 'function') {
        toggle.setAttribute('aria-expanded', value ? 'true' : 'false');
      }
    }

    function focusables() {
      return focusableWithin(drawer);
    }

    function focusElement(element) {
      if (isElement(element) && typeof element.focus === 'function') {
        element.focus();
        return true;
      }
      return false;
    }

    function onKeydown(event) {
      if (!openState || !event) return;
      const key = event.key;
      if (key === 'Escape' || key === 'Esc') {
        if (typeof event.preventDefault === 'function') event.preventDefault();
        if (typeof event.stopPropagation === 'function') event.stopPropagation();
        close();
        return;
      }
      if (key !== 'Tab') return;
      const items = focusables();
      if (!items.length) {
        if (typeof event.preventDefault === 'function') event.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = doc.activeElement;
      const contained = Boolean(drawer.contains && active && drawer.contains(active));
      if (event.shiftKey && (!contained || active === first)) {
        if (typeof event.preventDefault === 'function') event.preventDefault();
        focusElement(last);
      } else if (!event.shiftKey && (!contained || active === last)) {
        if (typeof event.preventDefault === 'function') event.preventDefault();
        focusElement(first);
      }
    }

    function bindKeys() {
      if (listening || typeof doc.addEventListener !== 'function') return;
      doc.addEventListener('keydown', onKeydown, true);
      listening = true;
    }

    function unbindKeys() {
      if (!listening || typeof doc.removeEventListener !== 'function') return;
      doc.removeEventListener('keydown', onKeydown, true);
      listening = false;
    }

    function open(trigger) {
      if (openState) return;
      openState = true;
      opener = isElement(trigger) ? trigger : (isElement(doc.activeElement) ? doc.activeElement : toggle);
      if (drawer.classList) drawer.classList.add('mobile-open');
      drawer.setAttribute('role', 'dialog');
      drawer.setAttribute('aria-modal', 'true');
      if (!drawer.hasAttribute('aria-label') && !drawer.hasAttribute('aria-labelledby')) {
        drawer.setAttribute('aria-label', 'Primary navigation');
      }
      if (backdrop && backdrop.classList) {
        backdrop.classList.remove('hidden');
        backdrop.setAttribute('aria-hidden', 'false');
      }
      setExpanded(true);
      bindKeys();
      const items = focusables();
      if (!focusElement(items[0])) {
        drawer.setAttribute('tabindex', '-1');
        focusElement(drawer);
      }
    }

    function close(closeOptions) {
      if (!openState) {
        setExpanded(false);
        return;
      }
      openState = false;
      if (drawer.classList) drawer.classList.remove('mobile-open');
      drawer.removeAttribute('role');
      drawer.removeAttribute('aria-modal');
      if (backdrop && backdrop.classList) {
        backdrop.classList.add('hidden');
        backdrop.setAttribute('aria-hidden', 'true');
      }
      setExpanded(false);
      unbindKeys();
      const restore = !closeOptions || closeOptions.restoreFocus !== false;
      const target = opener && (!doc.contains || doc.contains(opener)) ? opener : toggle;
      if (restore) focusElement(target);
      opener = null;
    }

    return {
      open: open,
      close: close,
      toggle: function () { if (openState) close(); else open(toggle); },
      isOpen: function () { return openState; },
      focusables: focusables,
      drawer: drawer,
      toggleElement: toggle,
      backdrop: backdrop
    };
  }

  function toastRegion(doc) {
    let region = doc.getElementById('toast-notification');
    if (!region) {
      region = doc.createElement('div');
      region.id = 'toast-notification';
      region.className = 'fixed bottom-6 right-6 z-50 px-5 py-3.5 rounded-2xl bg-[#1A1A1A] text-white text-xs font-bold shadow-2xl flex items-center gap-3 transition-all duration-300 transform translate-y-12 opacity-0 pointer-events-none border border-white/10';
      if (doc.body && typeof doc.body.appendChild === 'function') doc.body.appendChild(region);
    }
    region.setAttribute('role', 'status');
    region.setAttribute('aria-live', 'polite');
    region.setAttribute('aria-atomic', 'true');
    return region;
  }

  let toastTimer = null;

  function toast(message, options) {
    const opts = options || {};
    const doc = opts.document || root.document;
    if (!doc) return null;
    const region = toastRegion(doc);
    if (region.classList) TOAST_VISIBLE_CLASSES.forEach(name => region.classList.remove(name));
    // Clear first so an identical repeated message still mutates the live region.
    region.textContent = '';
    region.textContent = message === null || message === undefined ? '' : String(message);
    const timeout = opts.timeout === undefined ? 3200 : opts.timeout;
    if (toastTimer !== null && typeof root.clearTimeout === 'function') root.clearTimeout(toastTimer);
    if (timeout > 0 && typeof root.setTimeout === 'function') {
      toastTimer = root.setTimeout(function () {
        toastTimer = null;
        if (region.classList) TOAST_VISIBLE_CLASSES.forEach(name => region.classList.add(name));
      }, timeout);
    }
    return region;
  }

  function setActiveNavItem(tabId, options) {
    const doc = (options && options.document) || root.document;
    if (!doc || typeof doc.querySelectorAll !== 'function') return;
    doc.querySelectorAll('.sidebar-nav-item').forEach(item => {
      if (!isElement(item)) return;
      if (item.getAttribute('data-tab') === tabId) item.setAttribute('aria-current', 'page');
      else item.removeAttribute('aria-current');
    });
  }

  const api = {
    FOCUSABLE: FOCUSABLE,
    createDrawerController: createDrawerController,
    focusableWithin: focusableWithin,
    toast: toast,
    setActiveNavItem: setActiveNavItem
  };
  root.AgentScanA11y = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
