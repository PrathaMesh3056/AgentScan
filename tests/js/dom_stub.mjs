/* Minimal deterministic DOM used by the dashboard accessibility keyboard tests. */

class ClassList {
  constructor(element) { this.element = element; this.tokens = new Set(); }
  add(...names) { names.forEach(name => { if (name) this.tokens.add(name); }); this.sync(); }
  remove(...names) { names.forEach(name => this.tokens.delete(name)); this.sync(); }
  contains(name) { return this.tokens.has(name); }
  toggle(name, force) {
    const next = force === undefined ? !this.tokens.has(name) : Boolean(force);
    if (next) this.tokens.add(name); else this.tokens.delete(name);
    this.sync();
    return next;
  }
  sync() { this.element.attributes.class = Array.from(this.tokens).join(' '); }
  set(value) { this.tokens = new Set(String(value || '').split(/\s+/).filter(Boolean)); this.sync(); }
}

function splitSelectors(selector) {
  const parts = [];
  let depth = 0;
  let current = '';
  for (const char of String(selector)) {
    if (char === '[' || char === '(') depth += 1;
    if (char === ']' || char === ')') depth -= 1;
    if (char === ',' && depth === 0) { parts.push(current.trim()); current = ''; continue; }
    current += char;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function matchCompound(element, selector) {
  let rest = selector.trim();
  if (!rest) return false;
  const tag = /^([a-zA-Z][\w-]*|\*)/.exec(rest);
  if (tag) {
    if (tag[1] !== '*' && element.tagName.toLowerCase() !== tag[1].toLowerCase()) return false;
    rest = rest.slice(tag[0].length);
  }
  while (rest.length) {
    if (rest[0] === '#') {
      const match = /^#([\w-]+)/.exec(rest);
      if (!match) return false;
      if (element.getAttribute('id') !== match[1]) return false;
      rest = rest.slice(match[0].length);
      continue;
    }
    if (rest[0] === '.') {
      const match = /^\.([\w-]+)/.exec(rest);
      if (!match) return false;
      if (!element.classList.contains(match[1])) return false;
      rest = rest.slice(match[0].length);
      continue;
    }
    if (rest.startsWith(':not(')) {
      let depth = 0;
      let index = 4;
      for (; index < rest.length; index += 1) {
        if (rest[index] === '(') depth += 1;
        else if (rest[index] === ')') { depth -= 1; if (depth === 0) break; }
      }
      const inner = rest.slice(5, index);
      if (matchCompound(element, inner)) return false;
      rest = rest.slice(index + 1);
      continue;
    }
    if (rest[0] === ':') {
      const pseudo = /^:[\w-]+(\([^)]*\))?/.exec(rest);
      if (!pseudo) return false;
      rest = rest.slice(pseudo[0].length);
      continue;
    }
    if (rest[0] === '[') {
      const close = rest.indexOf(']');
      if (close === -1) return false;
      const body = rest.slice(1, close);
      const equals = body.indexOf('=');
      if (equals === -1) {
        if (element.getAttribute(body.trim()) === null) return false;
      } else {
        const name = body.slice(0, equals).trim();
        const expected = body.slice(equals + 1).trim().replace(/^["']|["']$/g, '');
        if (element.getAttribute(name) !== expected) return false;
      }
      rest = rest.slice(close + 1);
      continue;
    }
    return false;
  }
  return true;
}

export function matches(element, selector) {
  return splitSelectors(selector).some(part => matchCompound(element, part));
}

function descendants(element) {
  const found = [];
  element.children.forEach(child => { found.push(child, ...descendants(child)); });
  return found;
}

export class Element {
  constructor(document, tagName) {
    this.ownerDocument = document;
    this.tagName = String(tagName).toUpperCase();
    this.attributes = Object.create(null);
    this.children = [];
    this.parentNode = null;
    this.listeners = new Map();
    this.classList = new ClassList(this);
    this.hidden = false;
    this._text = '';
  }
  get id() { return this.getAttribute('id') || ''; }
  set id(value) { this.setAttribute('id', value); }
  get className() { return this.getAttribute('class') || ''; }
  set className(value) { this.classList.set(value); }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set textContent(value) {
    this._text = value === null || value === undefined ? '' : String(value);
    this.children = [];
  }
  setAttribute(name, value) {
    const text = String(value);
    if (name === 'class') { this.classList.set(text); return; }
    this.attributes[name] = text;
  }
  getAttribute(name) { return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null; }
  hasAttribute(name) { return this.getAttribute(name) !== null; }
  removeAttribute(name) {
    if (name === 'class') { this.classList.set(''); return; }
    delete this.attributes[name];
  }
  appendChild(child) {
    child.parentNode = this;
    child.ownerDocument = this.ownerDocument;
    this.children.push(child);
    return child;
  }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  contains(node) {
    if (!node) return false;
    if (node === this) return true;
    return this.children.some(child => child.contains(node));
  }
  focus() { this.ownerDocument.activeElement = this; }
  querySelectorAll(selector) { return descendants(this).filter(element => matches(element, selector)); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(handler);
  }
  removeEventListener(type, handler) {
    const handlers = this.listeners.get(type) || [];
    this.listeners.set(type, handlers.filter(item => item !== handler));
  }
  dispatchEvent(event) {
    (this.listeners.get(event.type) || []).forEach(handler => handler.call(this, event));
    return true;
  }
}

export class Document {
  constructor() {
    this.body = new Element(this, 'body');
    this.activeElement = this.body;
    this.listeners = new Map();
  }
  createElement(tagName) { return new Element(this, tagName); }
  getElementById(id) { return descendants(this.body).find(element => element.getAttribute('id') === id) || null; }
  querySelectorAll(selector) { return descendants(this.body).filter(element => matches(element, selector)); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  contains(node) { return node === this.body || this.body.contains(node); }
  addEventListener(type, handler) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(handler);
  }
  removeEventListener(type, handler) {
    const handlers = this.listeners.get(type) || [];
    this.listeners.set(type, handlers.filter(item => item !== handler));
  }
  dispatchEvent(event) {
    (this.listeners.get(event.type) || []).forEach(handler => handler.call(this, event));
    return true;
  }
}

export function createDocument() { return new Document(); }
