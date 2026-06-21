# Audits

Every rule `vuer` ships with, in the order the linter reports them.
The first column matches the `--min-severity` filter. "Works in" is
**template** for rules that walk `<template>`, **script** for rules
that walk `<script>`, and **both** for anything that runs in both
contexts.

## Rule table

| Rule | Severity | Category | Works in | Description |
|---|---|---|---|---|
| [`vue/security/no-v-html`](#vue-security-no-v-html) | Critical | security | template | Disallow the `v-html` directive to prevent XSS |
| [`vue/security/no-inner-html`](#vue-security-no-inner-html) | Critical | security | script | Disallow `el.innerHTML = ...` writes to prevent DOM XSS |
| [`vue/security/no-eval`](#vue-security-no-eval) | Critical | security | script | Disallow `eval(...)`, `new Function(...)`, and string `setTimeout`/`setInterval` |
| [`vue/security/no-dangerous-url`](#vue-security-no-dangerous-url) | Critical | security | template | Disallow `javascript:`, `data:text/html`, and `vbscript:` URLs |
| [`vue/security/no-document-write`](#vue-security-no-document-write) | High | security | script | Disallow `document.write` / `document.writeln` calls |
| [`vue/security/no-open-redirect`](#vue-security-no-open-redirect) | High | security | script | Disallow `location.href = ...` and `window.location = ...` with dynamic values |
| [`vue/security/no-unsafe-localstorage`](#vue-security-no-unsafe-localstorage) | High | security | script | Warn when an auth-looking value is written to `localStorage` |
| [`vue/security/no-dynamic-bind-src`](#vue-security-no-dynamic-bind-src) | High | security | template | Disallow dynamic `:src` bindings to prevent loading untrusted resources |
| [`vue/security/no-postmessage-wildcard`](#vue-security-no-postmessage-wildcard) | High | security | script | Disallow `postMessage(..., '*')` to prevent cross-origin message interception |
| [`vue/security/no-window-open-blank-noopener`](#vue-security-no-window-open-blank-noopener) | High | security | script | Disallow `window.open(url, '_blank', ...)` without `noopener` to prevent reverse tabnabbing |
| [`vue/security/no-fetch-without-timeout`](#vue-security-no-fetch-without-timeout) | High | security | script | Disallow `fetch(url)` without an `AbortSignal` to bound request lifetime |
| [`vue/security/no-unsafe-iframe`](#vue-security-no-unsafe-iframe) | Medium | security | template | Disallow `<iframe>` without a `sandbox` attribute |
| [`vue/best-practice/v-for-missing-key`](#vue-best-practice-v-for-missing-key) | Medium | best-practice | template | Require `:key` on `v-for` elements |
| [`vue/best-practice/no-inline-style`](#vue-best-practice-no-inline-style) | Low | best-practice | template | Disallow inline `style` and `:style` bindings in templates |
| [`vue/best-practice/no-watch-with-callback`](#vue-best-practice-no-watch-with-callback) | Low | best-practice | script | Warn about `watch(source, callback)` calls that may leak when not disposed |

---

## `vue/security/no-v-html`

| Field | Value |
|---|---|
| Severity | Critical |
| Category | security |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

The `v-html` directive tells Vue to inject a raw HTML string into
the DOM. The browser then parses the string as HTML, so any script
tags, event handlers, or `<iframe>` injections execute in the
origin of the page. There is no built-in sanitisation: anything
written by `v-html` is treated as trusted.

### Vulnerable

```vue
<template>
  <div v-html="userInput"></div>
</template>
```

`userInput` is attacker-controlled; the rendered HTML runs in your
origin.

### Safe

```vue
<template>
  <div>{{ userInput }}</div>
</template>
```

Vue interpolates the value as a text node, so the browser treats it
as text, not HTML.

### Remediation

* Replace `v-html` with text interpolation (`{{ ... }}`) if the
  value is plain text.
* If the value must contain HTML, sanitise it on the server (or
  with a vetted client-side library like [DOMPurify][1]) *before*
  it reaches the template. Never sanitise in `v-html` itself, that
  is a chicken-and-egg trap.

[1]: https://github.com/cure53/DOMPurify

---

## `vue/security/no-inner-html`

| Field | Value |
|---|---|
| Severity | Critical |
| Category | security |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

Assigning a string to `.innerHTML` is the script-level equivalent of
`v-html`: the browser parses the string as HTML and any script
content inside it runs in your origin. The linter flags every
write to a property literally named `innerHTML`, including
`a.b.innerHTML = ...`.

### Vulnerable

```js
const el = document.getElementById('preview')
el.innerHTML = userInput
```

### Safe

```js
el.textContent = userInput
```

### Remediation

* Use `textContent` for plain text.
* If the value must contain HTML, sanitise it with DOMPurify before
  assigning, and add a `// vuer-ignore[no-inner-html]` comment to
  silence the rule on that one line.

---

## `vue/security/no-eval`

| Field | Value |
|---|---|
| Severity | Critical |
| Category | security |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

`eval`, `new Function`, and the string forms of `setTimeout` and
`setInterval` execute their argument as JavaScript. If any
attacker-controlled substring reaches them, the attacker gets
arbitrary code execution in your origin.

### Vulnerable

```js
eval(input)
setTimeout("run(" + value + ")", 100)
const f = new Function("a", "b", body)
```

### Safe

```js
const fn = new Function("a", "b", body)  // body is a hard-coded literal
setTimeout(() => run(value), 100)
```

### Remediation

* Refactor to a static expression or a lookup table.
* If dynamic code is genuinely required, build a `Function` from a
  string the developer wrote, never from user input.

---

## `vue/security/no-dangerous-url`

| Field | Value |
|---|---|
| Severity | Critical |
| Category | security |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

`javascript:`, `data:text/html`, and `vbscript:` URLs execute
script content in the navigation target's origin when followed.
Only string literals are flagged — dynamic bindings require
data-flow analysis that the linter does not perform.

### Vulnerable

```vue
<a href="javascript:alert(1)">click</a>
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>
```

### Safe

```vue
<a href="/dashboard">click</a>
<iframe src="https://example.com/embed"></iframe>
```

### Remediation

* Use `https://` (or `/` for same-origin paths) for navigable URLs.
* If a dynamic scheme is genuinely required, validate it against an
  allow-list (`https`, `http`, `mailto`, `tel`) before binding.

---

## `vue/security/no-document-write`

| Field | Value |
|---|---|
| Severity | High |
| Category | security |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

`document.write` (and its sibling `document.writeln`) injects
arbitrary HTML at the current parse position. After the page has
finished loading it is almost always an XSS risk.

### Vulnerable

```js
document.write('<h1>' + name + '</h1>')
```

### Safe

```js
const heading = document.createElement('h1')
heading.textContent = name
document.body.appendChild(heading)
```

### Remediation

* Use DOM APIs (`appendChild`, `innerHTML` *with* sanitisation, or
  Vue reactivity) instead of `document.write`.

---

## `vue/security/no-open-redirect`

| Field | Value |
|---|---|
| Severity | High |
| Category | security |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

Writes to `location.href`, `window.location`, `window.location.href`,
or calls to `location.assign` / `location.replace` with a
non-literal argument are a classic open-redirect vector: an attacker
tricks the victim into clicking a link to your site, the script
copies the `?next=` query parameter into a navigation, and the
victim ends up on a phishing page that still appears to come from
your domain.

### Vulnerable

```js
location.href = nextParam
window.location = redirect
location.assign(redirect)
location.replace(redirect)
```

### Safe

```js
const allowed = new URL(nextParam, location.origin)
if (allowed.origin === location.origin) {
  location.href = allowed
}
```

### Remediation

* Validate the destination URL against an allow-list of hostnames
  before navigating.
* Use a router-managed navigation helper that always checks the
  same allow-list.

---

## `vue/security/no-unsafe-localstorage`

| Field | Value |
|---|---|
| Severity | High |
| Category | security |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

Auth tokens stored in `localStorage` are reachable by every
script running in the page, including any script an XSS payload
injects. The linter looks at the first argument of
`localStorage.setItem` and flags any name that contains `token`,
`jwt`, `secret`, or `auth` (or a variable name with those
substrings).

### Vulnerable

```js
localStorage.setItem('auth_token', jwt)
localStorage.setItem(secretKey, value)
```

### Safe

```js
// Server-set cookie with HttpOnly, Secure, SameSite=Lax.
document.cookie = `session=...; HttpOnly; Secure; SameSite=Lax`
```

### Remediation

* Use an `HttpOnly; Secure` cookie set by the server, not JS.
* If you genuinely need client-readable storage, use
  `sessionStorage` (cleared on tab close) and never put long-lived
  auth material there.

---

## `vue/security/no-dynamic-bind-src`

| Field | Value |
|---|---|
| Severity | High |
| Category | security |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

A dynamic `:src` binding (e.g. `:src="userAvatar"`) can load
attacker-controlled resources. Even if the URL is rendered inside
an `<img>`, a malicious value can still leak cookies, exfiltrate
referrer information, or perform SSRF against internal hosts when
the same pattern is reused for `<iframe>` or `<script>`.

The rule does **not** flag `:src` bound to a static-import value
(e.g. `import logo from './logo.svg'`), since the bundler controls
the URL.

### Vulnerable

```vue
<template>
  <img :src="userAvatar">
  <iframe :src="iframeUrl"></iframe>
</template>
```

### Safe

```vue
<template>
  <img :src="logo">
  <img :src="'/avatars/' + sanitizedId + '.png'">
</template>
```

### Remediation

* Validate the URL against an allow-list of schemes and hosts
  before binding.
* For `<img>`, restrict the URL to a path on your own origin
  whenever possible.

---

## `vue/security/no-postmessage-wildcard`

| Field | Value |
|---|---|
| Severity | High |
| Category | security |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

`postMessage` is a safe cross-origin communication channel *only*
when the caller pins a specific `targetOrigin`. Passing the literal
`'*'` (or the options-object equivalent) tells the browser to
deliver the message to whichever window happens to be there —
including a window an attacker has just navigated to the same
name.

Both the legacy `postMessage(msg, targetOrigin)` form and the
options form `postMessage(msg, { targetOrigin })` are checked.

### Vulnerable

```js
iframe.contentWindow.postMessage({ type: 'ping' }, '*')
window.postMessage('hello', '*')
popup.postMessage(payload, { targetOrigin: '*' })
```

### Safe

```js
iframe.contentWindow.postMessage({ type: 'ping' }, 'https://app.example.com')
window.postMessage('hello', '/')  // same-origin delivery only
```

### Remediation

* Pin the receiver's exact origin (e.g. `https://app.example.com`).
* Use `/` if you genuinely want same-origin delivery only.
* The receiver **must** also check `event.origin` before trusting
  the message.

---

## `vue/security/no-window-open-blank-noopener`

| Field | Value |
|---|---|
| Severity | High |
| Category | security |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

`window.open(url, '_blank', ...)` without `noopener` (or
`noreferrer`, which implies `noopener`) in the `windowFeatures`
string lets the opened tab call `window.opener.location = ...` and
phish the originating page. This is the "reverse tabnabbing"
attack.

The rule fires only on `window.open` (not on `popup.open` or other
`.open()` calls) and only when the target is the literal `'_blank'`.

### Vulnerable

```js
window.open('https://example.com', '_blank')
window.open('https://example.com', '_blank', 'width=400,height=300')
```

### Safe

```js
window.open('https://example.com', '_blank', 'noopener')
window.open('https://example.com', '_blank', 'noreferrer')
```

### Remediation

* Add `noopener` to the `windowFeatures` string.
* `noreferrer` also works (it implies `noopener` plus omits the
  `Referer` header).

---

## `vue/security/no-fetch-without-timeout`

| Field | Value |
|---|---|
| Severity | High |
| Category | security |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

A `fetch` call that is never aborted can hang indefinitely on a
slow or unreachable host, exhausting connection pools and tying up
UI state. The modern remediation is to pass
`signal: controller.signal` in the options object, then call
`controller.abort()` from a `setTimeout`, a navigation event, or a
Vue lifecycle hook.

The rule flags:
* every global `fetch(url)` call (no `signal` can be attached
  after the fact),
* every `fetch(url, { ...options })` call where the options object
  does not contain a `signal` property,
* and only the global `fetch` — custom methods on third-party
  objects (e.g. `api.fetch(...)`) are not flagged.

### Vulnerable

```js
fetch('/api/users')
fetch('/api/users', { method: 'POST', headers: { 'Content-Type': 'application/json' } })
```

### Safe

```js
const ctrl = new AbortController()
setTimeout(() => ctrl.abort(), 5_000)
fetch('/api/users', { signal: ctrl.signal })
```

### Remediation

* Wrap every `fetch` in an `AbortController` and pair the call with
  a `setTimeout` (or a Vue lifecycle hook) that aborts on cleanup.

---

## `vue/security/no-unsafe-iframe`

| Field | Value |
|---|---|
| Severity | Medium |
| Category | security |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

An `<iframe>` without a `sandbox` attribute inherits the embedding
origin's full capabilities. A malicious page that turns the
iframe into a phishing form (for example, by navigating it to
`/login`) can exfiltrate whatever the victim types in.

### Vulnerable

```vue
<iframe src="https://example.com/embed"></iframe>
```

### Safe

```vue
<iframe src="https://example.com/embed" sandbox></iframe>
<iframe src="https://example.com/embed" sandbox="allow-scripts allow-same-origin"></iframe>
```

### Remediation

* Add at minimum `sandbox=""` (no permissions) to neutralise the
  framed content. Open the allow-list back up one token at a time
  (`allow-scripts`, `allow-same-origin`, ...) and only when you
  genuinely need them.

---

## `vue/best-practice/v-for-missing-key`

| Field | Value |
|---|---|
| Severity | Medium |
| Category | best-practice |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

Without a stable `:key` on a `v-for`, Vue falls back to
index-based reconciliation. Reordering, inserting, or removing an
item then produces wrong DOM updates and loses component state
(local input, focus, scroll position, animations).

### Vulnerable

```vue
<ul>
  <li v-for="item in items">{{ item.label }}</li>
</ul>
```

### Safe

```vue
<ul>
  <li v-for="item in items" :key="item.id">{{ item.label }}</li>
</ul>
```

### Remediation

* Bind `:key` to a stable identifier from the data (database id,
  slug, hash), never the array index.

---

## `vue/best-practice/no-inline-style`

| Field | Value |
|---|---|
| Severity | Low |
| Category | best-practice |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

Inline `style` and `:style` bindings bypass the cascade, prevent
theming, and tend to grow as the component evolves. Most style
concerns are better expressed as a class on a stylesheet rule.

### Vulnerable

```vue
<template>
  <div style="color: red; font-size: 14px;">Alert</div>
  <div :style="{ color: count > 0 ? 'green' : 'gray' }">Count: {{ count }}</div>
</template>
```

### Safe

```vue
<template>
  <div class="alert">Alert</div>
  <div :class="count > 0 ? 'positive' : 'neutral'">Count: {{ count }}</div>
</template>
```

### Remediation

* Move the rule into a CSS class. Bind `:class` instead of `:style`
  when the value changes dynamically.

---

## `vue/best-practice/no-watch-with-callback`

| Field | Value |
|---|---|
| Severity | Low |
| Category | best-practice |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.1.0 |

`watch(source, callback)` returns a stop handle that is easy to
forget to call. When the component unmounts (or the reactive
source goes out of scope) without the handle being called, the
watcher keeps observing and the callback can leak memory or fire
against a stale `this`.

The rule flags every `watch` call whose second argument is a
function expression (arrow or function) and which does **not** use
the stop handle in the same expression.

### Vulnerable

```js
watch(count, (newVal) => {
  console.log('Count changed:', newVal)
})
```

### Safe

```js
const stop = watch(count, (newVal) => {
  console.log('Count changed:', newVal)
})
onScopeDispose(stop)
```

### Remediation

* Prefer `watchEffect` if you do not need a stop handle — the
  watcher is automatically disposed on scope teardown.
* If you need `watch`, store the returned handle and call it in
  `onScopeDispose` or `onUnmounted`.
