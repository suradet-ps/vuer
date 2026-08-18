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
| [`vue/security/no-window-open-blank-noopener`](#vue-security-no-window-open-blank-noopener) | High | security | script | Disallow `window.open(url, '_blank', ...)` without `noopener` when the URL may carry untrusted data |
| [`vue/security/no-fetch-without-timeout`](#vue-security-no-fetch-without-timeout) | High | security | script | Disallow `fetch(url)` without an `AbortSignal` to bound request lifetime |
| [`vue/security/no-unsafe-iframe`](#vue-security-no-unsafe-iframe) | Medium | security | template | Disallow `<iframe>` without a `sandbox` attribute |
| [`vue/best-practice/v-for-missing-key`](#vue-best-practice-v-for-missing-key) | Medium | best-practice | template | Require `:key` on `v-for` elements |
| [`vue/best-practice/no-inline-style`](#vue-best-practice-no-inline-style) | Low | best-practice | template | Disallow inline `style` and `:style` bindings in templates |
| [`vue/best-practice/no-watch-with-callback`](#vue-best-practice-no-watch-with-callback) | Low | best-practice | script | Warn about `watch(source, callback)` calls at module scope that have no owner to dispose them |
| [`vue/performance/no-v-if-with-v-for`](#vue-performance-no-v-if-with-v-for) | Medium | performance | template | Disallow `v-if` together with `v-for` on the same element |
| [`vue/performance/no-deep-watch-without-handler`](#vue-performance-no-deep-watch-without-handler) | Low | performance | script | Warn about `watch(source, callback, { deep: true })` watchers that traverse the whole object on every change |
| [`vue/performance/no-reactive-in-v-for`](#vue-performance-no-reactive-in-v-for) | Low | performance | script | Disallow reactive object creation inside loop bodies |
| [`vue/performance/no-large-list-without-virtualization`](#vue-performance-no-large-list-without-virtualization) | Low | performance | template | Heuristic: `v-for` over a large-looking collection without a virtual-scroll wrapper |
| [`vue/accessibility/no-img-without-alt`](#vue-accessibility-no-img-without-alt) | Medium | accessibility | template | Require an `alt` attribute on every `<img>` |
| [`vue/accessibility/no-click-without-role-keyboard`](#vue-accessibility-no-click-without-role-keyboard) | Medium | accessibility | template | Require `role` and a keyboard handler on `@click` of non-interactive elements |
| [`vue/accessibility/no-form-without-label`](#vue-accessibility-no-form-without-label) | Medium | accessibility | template | Require an associated `<label>` or `aria-label` on form fields |
| [`vue/accessibility/no-button-without-type`](#vue-accessibility-no-button-without-type) | Low | accessibility | template | Require an explicit `type` on every `<button>` |
| [`vue/architecture/no-side-effect-in-computed`](#vue-architecture-no-side-effect-in-computed) | Medium | architecture | script | Disallow side effects inside `computed(...)` getters |
| [`vue/architecture/no-mutation-of-props`](#vue-architecture-no-mutation-of-props) | Medium | architecture | script | Disallow writes to props declared with `defineProps` |
| [`vue/architecture/no-async-setup-without-error-boundary`](#vue-architecture-no-async-setup-without-error-boundary) | Low | architecture | both | Heuristic: `async setup()` without a `<Suspense>` boundary |

---

## Taint analysis (Phase 2)

Four rules — `no-v-html`, `no-inner-html`, `no-dynamic-bind-src`, and
`no-open-redirect` — do not merely match a pattern; they ask whether the
matched pattern *carries untrusted data*. A single-pass taint engine runs
once per file (at parse time) and annotates every expression with one of:

* **Tainted** — the value flows from a recognised source: `localStorage` /
  `sessionStorage` reads, `fetch` / `axios` / `useFetch` responses,
  `useRoute()` / `$route` params and query, `defineProps` props, `event` /
  `$event` payloads, `window.location`, `location.search`/`hash`,
  `document.cookie` / `document.referrer`, `document.*` DOM reads,
  `new FormData()` / `URLSearchParams`.
* **Clean** — a literal, or a value derived only from clean data
  (including values passed through a recognised sanitizer:
  `DOMPurify.sanitize`, `sanitize`, `escapeHtml`, `htmlEscape`, `escape`,
  `xss`).
* **Unknown** — the expression could not be analysed (e.g. an unparseable
  template binding); sink rules report these conservatively.

Taint propagates through assignments, concatenation, template literals,
ternaries, member writes/reads, destructuring, `.map`/`.filter`/`.then`
callbacks, `ref`/`reactive`/`computed` wrappers, and bounded
inter-procedural flow through local function calls. A call to an
*unknown* function never taints its result (it could be a sanitizer) —
cross-file flow through imports/composables is deferred to Phase 6.

When a tainted value reaches a sink, the diagnostic carries the flow:

```text
error[vue/security/no-v-html]: Unsafe `v-html` directive renders untrusted HTML
  = note: taint from localStorage.getItem (line 12) reaches `v-html` binding via userInput
```

This is what turns "this pattern exists" into "this pattern carries
untrusted data": clean bindings are no longer reported (the
false-positive cut), while the unsafe path is always reported.

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
<script setup>
const userInput = localStorage.getItem('draft')
</script>

<template>
  <div v-html="userInput"></div>
</template>
```

`userInput` flows from `localStorage` (untrusted) into the `v-html`
binding. The diagnostic reports the flow:
``taint from localStorage.getItem (line 2) reaches `v-html` binding via userInput``.

### Not reported (the false-positive cut)

Since v0.2 the rule only fires on bindings that may carry untrusted
data. These are **not** reported:

```vue
<template>
  <div v-html="'<b>static</b>'"></div>   <!-- literal -->
  <div v-html="safe"></div>              <!-- sanitized: DOMPurify.sanitize(...) -->
</template>
```

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
This rule is intentionally **syntactic** (it checks the URL scheme
of the literal/binding text, not data flow): the dangerous pattern
here *is* the scheme itself, so the taint-gating that Phase 2
applies to `no-v-html` / `no-inner-html` / `no-dynamic-bind-src` /
`no-open-redirect` would be wrong — a `javascript:` URL is dangerous
whether its source is trusted or not. Dynamic untrusted *URLs* are
covered by `no-open-redirect` (navigation) and `no-dynamic-bind-src`
(resource loading).

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
or calls to `location.assign` / `location.replace` with a value that
may carry untrusted data (see
[Taint analysis](#taint-analysis-phase-2)) are a classic open-redirect
vector: an attacker
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

Since v0.2 the rule only fires when the bound value may carry
untrusted data (see [Taint analysis](#taint-analysis-phase-2));
constant or static-import values (`import logo from './logo.svg'`)
are not reported.

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

**Taint-gated (Phase 2).** Reverse tabnabbing only bites when the
opened page is attacker-influenced. A URL that is provably clean — a
hardcoded literal or a value derived only from trusted data — opens a
page the developer chose, so the finding is dropped. A URL carrying
untrusted data (route query, `localStorage`, props, ...) is reported
at High with the source→sink flow path; an unanalysable URL is
reported conservatively.

### Vulnerable

```js
const url = localStorage.getItem('next')
window.open(url, '_blank')
window.open(route.query.url, '_blank', 'width=400,height=300')
```

### Safe

```js
window.open('https://example.com', '_blank')
window.open('https://example.com', '_blank', 'noopener')
window.open('https://example.com', '_blank', 'noreferrer')
const url = localStorage.getItem('next')
window.open(url, '_blank', 'noopener')
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

Vue 3 disposes watchers automatically when they are created inside a
component scope:

* `<script setup>` — every top-level statement runs inside the
  component's setup scope; watchers are stopped with the component.
* Options API — `this.$watch` is bound to the instance and stopped on
  unmount; a `watch()` call inside `setup()`/`created()`/... is
  equally owned by the instance.

The one place a `watch(source, callback)` call genuinely leaks is
**module scope** in a plain `<script>` block (no `setup` attribute):
the watcher is created once when the module loads, has no component
lifecycle to be torn down with, and keeps its closure alive until the
page unloads.

The rule flags only module-scope `watch` calls whose second argument
is a function expression (arrow or function). In `<script setup>`
nothing is reported — Vue disposes setup-scope watchers with the
component.

### Vulnerable

```js
// module scope in a plain <script> block
watch(count, (newVal) => {
  console.log('Count changed:', newVal)
})
```

### Safe

```js
// <script setup>: disposed automatically with the component
watch(count, (newVal) => {
  console.log('Count changed:', newVal)
})

// module scope: store the handle and stop it explicitly
const stop = watch(count, (newVal) => {
  console.log('Count changed:', newVal)
})
stop()
```

### Remediation

* Move the `watch` into the component (a `<script setup>` block or an
  Options API lifecycle hook), where Vue disposes it automatically.
* If module scope is required, store the returned stop handle and call
  it when the watcher is no longer needed.

---

## `vue/performance/no-v-if-with-v-for`

| Field | Value |
|---|---|
| Severity | Medium |
| Category | performance |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

Vue 3 evaluates `v-if` before `v-for` on the same element, so the list
is built and then discarded when the condition is false. The pair is
also a well-known source of priority bugs when code is ported from
Vue 2, where the order was reversed. The documented pattern is to
filter the list with a computed property and keep `v-if` on a wrapper.

### Vulnerable

```vue
<ul>
  <li v-for="item in items" v-if="item.active">{{ item.label }}</li>
</ul>
```

### Safe

```vue
<script setup>
const activeItems = computed(() => items.filter((i) => i.active))
</script>

<template>
  <ul>
    <li v-for="item in activeItems" :key="item.id">{{ item.label }}</li>
  </ul>
</template>
```

### Remediation

* Move the filter into a `computed` and iterate the filtered list.

---

## `vue/performance/no-deep-watch-without-handler`

| Field | Value |
|---|---|
| Severity | Low |
| Category | performance |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

A `watch(source, callback, { deep: true })` watcher re-compares every
nested property of the watched object on each mutation. The cost grows
with the object graph, and the comparison runs on the main thread.
Prefer watching an explicit path, or `{ once: true }` when only the
first notification matters (Vue 3.4+).

Scope boundary: only the composition `watch()` form with an inline
options object is analysed. Options API `watch: { key: { deep: true } }`
declarations and options objects stored in a variable are not resolved.

### Vulnerable

```js
watch(user, (u) => save(u), { deep: true })
```

### Safe

```js
watch(() => user.profile, (profile) => save(profile))
watch(user, (u) => save(u), { deep: true, once: true })
```

### Remediation

* Watch `() => obj.field` paths instead of the whole object.
* Add `{ once: true }` when the watcher only needs the first change.

---

## `vue/performance/no-reactive-in-v-for`

| Field | Value |
|---|---|
| Severity | Low |
| Category | performance |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

Creating `ref` / `reactive` / `shallowRef` / `shallowReactive` /
`computed` wrappers inside a loop body (a `for` / `for...of` /
`for...in` statement or an array-iteration callback such as `map`,
`filter`, `forEach`, `reduce`) allocates a fresh wrapper and effect per
iteration. The wrappers are not owned by Vue's render tree, so they are
never released when the list changes — a silent per-render leak that
grows with list size.

### Vulnerable

```js
const wrapped = items.map((item) => reactive(item))
```

### Safe

```js
// Keep plain per-item values; the render derives them on demand.
const doubled = items.map((item) => item * 2)
```

### Remediation

* Hoist the reactive wrapper out of the loop.
* Store plain values per item and wrap the whole collection once.

---

## `vue/performance/no-large-list-without-virtualization`

| Field | Value |
|---|---|
| Severity | Low |
| Category | performance |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

**Heuristic, best-effort.** Rendering tens of thousands of DOM nodes
freezes the main thread. The rule fires only when **both** of these
hold:

1. the `v-for` source is a bare identifier whose name is in a curated
   list of collection names that typically come from a backend
   (`users`, `messages`, `rows`, `logs`, `transactions`, ...), and
2. neither the element nor any ancestor is a known virtual-scroll
   wrapper (element name containing `virtual` / `scroller`, e.g.
   `RecycleScroller`, `el-virtual-list`, `v-virtual-scroll`).

Generic names (`items`, `colors`, `steps`), computed slices, and
function results are deliberately ignored to keep the false-positive
rate low.

### Vulnerable

```vue
<ul>
  <li v-for="user in users" :key="user.id">{{ user.name }}</li>
</ul>
```

### Safe

```vue
<RecycleScroller :items="users">
  <template #default="{ item }">
    <li>{{ item.name }}</li>
  </template>
</RecycleScroller>
```

### Remediation

* Wrap the list in a virtual-scroll component or paginate.
* If the collection is provably small, silence with
  `vuer-ignore[no-large-list-without-virtualization]`.

---

## `vue/accessibility/no-img-without-alt`

| Field | Value |
|---|---|
| Severity | Medium |
| Category | accessibility |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

Screen readers announce the `alt` text in place of the image; an image
without `alt` is announced as its filename or skipped entirely. An
explicit empty `alt=""` is intentional (decorative image) and is
accepted, as are bound forms (`:alt`, `v-bind:alt`) and a bare
`v-bind="attrs"` spread that could carry the attribute.

### Vulnerable

```vue
<img src="logo.png">
```

### Safe

```vue
<img src="logo.png" alt="Vuer logo">
<img src="divider.png" alt="">
<img :src="avatar" :alt="user.name">
```

### Remediation

* Add descriptive `alt` text; use `alt=""` for decorative images.

---

## `vue/accessibility/no-click-without-role-keyboard`

| Field | Value |
|---|---|
| Severity | Medium |
| Category | accessibility |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

An element that reacts to clicks but cannot receive keyboard focus is
unreachable for keyboard-only users. The rule reports only the
clear-cut case — a `@click`/`v-on:click` handler on a non-interactive
element with **neither** a `role` **nor** any keyboard handler
(`@keydown`, `@keyup`, `@keypress`). Native interactive elements
(`a`, `button`, `input`, `select`, `textarea`, `label`, `details`,
`summary`, `option`, `audio`, `video`) are never reported.

### Vulnerable

```vue
<div @click="open()">Open</div>
```

### Safe

```vue
<button type="button" @click="open()">Open</button>

<div role="button" tabindex="0" @click="open()" @keydown.enter="open()">Open</div>
```

### Remediation

* Use a real interactive element (`<button>`, `<a href>`).
* Or add `role`, `tabindex="0"`, and a matching keyboard handler.

---

## `vue/accessibility/no-form-without-label`

| Field | Value |
|---|---|
| Severity | Medium |
| Category | accessibility |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

An unlabelled form field is announced only as its type by screen
readers. A field is considered labelled when any of these holds:

1. it carries `aria-label` or `aria-labelledby` (static or bound),
2. its `id` matches the `for` of some `<label>` in the template,
3. it is wrapped inside a `<label>` element,
4. it carries a bare `v-bind="attrs"` / dynamic `:[key]` binding that
   could supply a label (unprovable → accepted).

`type="hidden"` inputs are skipped. Labels from other files (slots,
partials, composables) are not resolved — documented boundary.

### Vulnerable

```vue
<input type="text" v-model="name">
```

### Safe

```vue
<label for="name">Name</label>
<input id="name" type="text" v-model="name">

<label>
  Name <input type="text" v-model="name">
</label>

<input type="text" aria-label="Name" v-model="name">
```

### Remediation

* Associate a `<label for="field-id">`, wrap in `<label>`, or add
  `aria-label` / `aria-labelledby`.

---

## `vue/accessibility/no-button-without-type`

| Field | Value |
|---|---|
| Severity | Low |
| Category | accessibility |
| Works in | template |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

A `<button>` without `type` defaults to `type="submit"`. Inside a form,
any click — including one meant to collapse a panel or clear the form —
submits the form and navigates.

### Vulnerable

```vue
<button @click="count++">+</button>
```

### Safe

```vue
<button type="button" @click="count++">+</button>
<button type="submit">Save</button>
```

### Remediation

* Set `type="button"` for in-page actions, or `type="submit"` (or
  `type="reset"`) explicitly when that is the intent.

---

## `vue/architecture/no-side-effect-in-computed`

| Field | Value |
|---|---|
| Severity | Medium |
| Category | architecture |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

A computed getter must be a pure function of reactive state: Vue
re-evaluates it lazily and possibly re-runs it on every dependency
change, so anything it mutates, writes, or fires happens an
unpredictable number of times. The rule flags:

* assignment / update expressions (`x = 1`, `x++`, `x += y`),
* calls to mutating collection / DOM methods (`push`, `splice`, `set`,
  `remove`, ...),
* calls to side-effecting APIs (`fetch`, `console.*`, `watch`,
  `setTimeout`, `axios.*`, `emit`, ...),
* `async` getters (Vue cannot await a computed — the getter returns a
  Promise, not the value).

Nested function bodies are deliberately not descended into: a helper
that happens to be *declared* inside the getter is not executed during
evaluation. Options API `computed: { ... }` declarations are out of
scope.

### Vulnerable

```js
const doubled = computed(() => {
  count++
  return count * 2
})

const data = computed(async () => fetch('/api'))
```

### Safe

```js
const doubled = computed(() => count * 2)

watch(count, () => {
  count++
})
```

### Remediation

* Move the side effect to a `watch` or an event handler.

---

## `vue/architecture/no-mutation-of-props`

| Field | Value |
|---|---|
| Severity | Medium |
| Category | architecture |
| Works in | script |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

Props are read-only one-way data flow: the parent owns the state. A
write (`props.x = 1`, `props.x++`, or an assignment to a destructured
prop) silently diverges the child from the parent — Vue logs a dev-time
warning and the change is lost on the next parent re-render.

Detection covers `<script setup>`: `const props = defineProps(...)` /
`withDefaults(defineProps(...), ...)` member writes, and writes to
props destructured via `const { a, b } = defineProps(...)`.
Options API `this.x = ...` writes are out of scope.

### Vulnerable

```js
const props = defineProps({ msg: String })
props.msg = 'replaced'
```

### Safe

```js
const props = defineProps({ msg: String })
const emit = defineEmits(['update:msg'])

emit('update:msg', 'replaced')
```

### Remediation

* `emit` an event and let the parent update its own state.

---

## `vue/architecture/no-async-setup-without-error-boundary`

| Field | Value |
|---|---|
| Severity | Low |
| Category | architecture |
| Works in | both |
| Auto-fixable | no |
| Introduced in | v0.3.0 (Phase 3) |

**Heuristic, low severity.** Vue 3 requires an `async setup()`
component to be wrapped in `<Suspense>` at the *parent* to show a
loading fallback while the promise resolves; without it the component
renders nothing until the promise settles. The rule cannot see the
parent's template, so it uses the component's own template as a proxy:
an `async setup()` with no `<Suspense>` in the same file is reported.

Detection: any async function named `setup` in an object literal
(`export default { async setup() {} }`, `setup: async () => {}`,
`defineComponent({ ... })`, ...).

### Vulnerable

```js
export default {
  async setup() {
    const data = await load()
    return { data }
  },
}
```

### Safe

```vue
<template>
  <Suspense>
    <ChildComponent />
  </Suspense>
</template>
```

If the component is always mounted inside a router-level `Suspense`,
silence the finding:

```vue
<!-- vuer-ignore[no-async-setup-without-error-boundary] -->
<script>
export default {
  async setup() { /* ... */ },
}
</script>
```

### Remediation

* Wrap the component (or its router outlet) in `<Suspense>`.
