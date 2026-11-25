/* Keyboard and DOM regressions for issue #40 (QA-183 through QA-186). */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

import { createDocument } from './dom_stub.mjs';

const require = createRequire(import.meta.url);
const a11y = require('../../agentscan/ui/static/dashboard-a11y.js');

function buildFixture() {
  const doc = createDocument();
  const sidebar = doc.createElement('aside');
  sidebar.id = 'sidebar';
  sidebar.setAttribute('aria-label', 'Primary navigation');
  const brand = doc.createElement('a');
  brand.setAttribute('href', '#overview');
  brand.textContent = 'AgentScan';
  sidebar.appendChild(brand);
  const nav = doc.createElement('nav');
  nav.setAttribute('aria-label', 'Primary');
  sidebar.appendChild(nav);
  const links = ['overview', 'findings', 'pipelines'].map(tab => {
    const link = doc.createElement('a');
    link.setAttribute('href', `#${tab}`);
    link.setAttribute('data-tab', tab);
    link.className = 'sidebar-nav-item';
    link.textContent = tab;
    nav.appendChild(link);
    return link;
  });
  links[0].setAttribute('aria-current', 'page');
  const collapse = doc.createElement('button');
  collapse.id = 'btn-toggle-sidebar';
  collapse.textContent = 'Collapse';
  nav.appendChild(collapse);
  const toggle = doc.createElement('button');
  toggle.id = 'btn-mobile-menu';
  toggle.setAttribute('aria-controls', 'sidebar');
  toggle.setAttribute('aria-expanded', 'false');
  toggle.textContent = 'Menu';
  const backdrop = doc.createElement('div');
  backdrop.id = 'sidebar-backdrop';
  backdrop.className = 'hidden';
  backdrop.setAttribute('aria-hidden', 'true');
  const outside = doc.createElement('button');
  outside.id = 'outside-action';
  outside.textContent = 'Outside';
  doc.body.append(toggle, backdrop, sidebar, outside);
  return { doc, sidebar, nav, brand, links, collapse, toggle, backdrop, outside };
}

function keydown(doc, key, options = {}) {
  const event = {
    type: 'keydown',
    key,
    shiftKey: Boolean(options.shiftKey),
    defaultPrevented: false,
    propagationStopped: false,
    preventDefault() { this.defaultPrevented = true; },
    stopPropagation() { this.propagationStopped = true; }
  };
  doc.dispatchEvent(event);
  return event;
}

function controllerFor(fixture) {
  return a11y.createDrawerController({
    document: fixture.doc,
    drawer: fixture.sidebar,
    toggle: fixture.toggle,
    backdrop: fixture.backdrop
  });
}

test('opening the drawer enters focus and exposes expanded dialog semantics', () => {
  const fixture = buildFixture();
  const controller = controllerFor(fixture);
  fixture.toggle.focus();
  controller.open(fixture.toggle);
  assert.equal(controller.isOpen(), true);
  assert.equal(fixture.doc.activeElement, fixture.brand, 'focus enters the drawer');
  assert.equal(fixture.toggle.getAttribute('aria-expanded'), 'true');
  assert.equal(fixture.toggle.getAttribute('aria-controls'), 'sidebar');
  assert.equal(fixture.sidebar.getAttribute('role'), 'dialog');
  assert.equal(fixture.sidebar.getAttribute('aria-modal'), 'true');
  assert.equal(fixture.backdrop.classList.contains('hidden'), false);
  assert.equal(fixture.backdrop.getAttribute('aria-hidden'), 'false');
});

test('Tab and Shift+Tab stay inside the open drawer', () => {
  const fixture = buildFixture();
  const controller = controllerFor(fixture);
  controller.open(fixture.toggle);

  fixture.collapse.focus();
  const forward = keydown(fixture.doc, 'Tab');
  assert.equal(forward.defaultPrevented, true, 'Tab from the last control is trapped');
  assert.equal(fixture.doc.activeElement, fixture.brand, 'Tab wraps to the first control');

  fixture.brand.focus();
  const backward = keydown(fixture.doc, 'Tab', { shiftKey: true });
  assert.equal(backward.defaultPrevented, true, 'Shift+Tab from the first control is trapped');
  assert.equal(fixture.doc.activeElement, fixture.collapse, 'Shift+Tab wraps to the last control');

  fixture.links[1].focus();
  const middle = keydown(fixture.doc, 'Tab');
  assert.equal(middle.defaultPrevented, false, 'Tab between drawer controls is not blocked');
});

test('Escape closes the drawer and restores focus to the opener', () => {
  const fixture = buildFixture();
  const controller = controllerFor(fixture);
  fixture.toggle.focus();
  controller.open(fixture.toggle);
  fixture.links[1].focus();

  const escape = keydown(fixture.doc, 'Escape');
  assert.equal(escape.defaultPrevented, true);
  assert.equal(controller.isOpen(), false);
  assert.equal(fixture.sidebar.classList.contains('mobile-open'), false);
  assert.equal(fixture.sidebar.getAttribute('role'), null);
  assert.equal(fixture.sidebar.getAttribute('aria-modal'), null);
  assert.equal(fixture.toggle.getAttribute('aria-expanded'), 'false');
  assert.equal(fixture.backdrop.classList.contains('hidden'), true);
  assert.equal(fixture.doc.activeElement, fixture.toggle, 'focus returns to the menu button');
});

test('closing restores the element that opened the drawer', () => {
  const fixture = buildFixture();
  const controller = controllerFor(fixture);
  fixture.outside.focus();
  controller.open(fixture.outside);
  assert.equal(fixture.doc.activeElement, fixture.brand);
  controller.close();
  assert.equal(fixture.doc.activeElement, fixture.outside, 'focus returns to the invoking control');
  assert.equal(fixture.toggle.getAttribute('aria-expanded'), 'false');
});

test('Escape and Tab do nothing while the drawer is closed', () => {
  const fixture = buildFixture();
  controllerFor(fixture);
  fixture.outside.focus();
  const escape = keydown(fixture.doc, 'Escape');
  assert.equal(escape.defaultPrevented, false);
  assert.equal(fixture.doc.activeElement, fixture.outside);
  const tab = keydown(fixture.doc, 'Tab');
  assert.equal(tab.defaultPrevented, false);
});

test('hidden controls are excluded from the focus loop', () => {
  const fixture = buildFixture();
  const hidden = fixture.doc.createElement('button');
  hidden.id = 'hidden-action';
  hidden.hidden = true;
  fixture.nav.appendChild(hidden);
  const controller = controllerFor(fixture);
  const focusables = controller.focusables();
  assert.equal(focusables.includes(hidden), false);
  assert.equal(focusables[0], fixture.brand);
  assert.equal(focusables[focusables.length - 1], fixture.collapse);
});

test('toasts are announced through a polite atomic live region', () => {
  const fixture = buildFixture();
  const region = a11y.toast('Report download failed.', { document: fixture.doc, timeout: 0 });
  assert.ok(region, 'toast returns the live region');
  assert.equal(region.getAttribute('role'), 'status');
  assert.equal(region.getAttribute('aria-live'), 'polite');
  assert.equal(region.getAttribute('aria-atomic'), 'true');
  assert.equal(region.textContent, 'Report download failed.');
  assert.equal(region.classList.contains('opacity-0'), false);
  assert.equal(region.classList.contains('translate-y-12'), false);
  a11y.toast('Report download failed.', { document: fixture.doc, timeout: 0 });
  assert.equal(region.textContent, 'Report download failed.', 'repeated messages are re-inserted');
});

test('toast hides itself after the display window', async () => {
  const fixture = buildFixture();
  a11y.toast('Telemetry refreshed', { document: fixture.doc, timeout: 5 });
  const region = fixture.doc.getElementById('toast-notification');
  assert.equal(region.classList.contains('opacity-0'), false);
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(region.classList.contains('opacity-0'), true);
  assert.equal(region.classList.contains('translate-y-12'), true);
});

test('the active navigation item carries aria-current=page', () => {
  const fixture = buildFixture();
  a11y.setActiveNavItem('findings', { document: fixture.doc });
  assert.equal(fixture.links[1].getAttribute('aria-current'), 'page');
  assert.equal(fixture.links[0].getAttribute('aria-current'), null);
  assert.equal(fixture.links[2].getAttribute('aria-current'), null);
  a11y.setActiveNavItem('pipelines', { document: fixture.doc });
  assert.equal(fixture.links[2].getAttribute('aria-current'), 'page');
  assert.equal(fixture.links[1].getAttribute('aria-current'), null);
});
