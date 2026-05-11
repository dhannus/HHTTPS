---
name: Bug report
about: Report a bug in HHTTPS server, browser extension, or SDKs
title: '[BUG] '
labels: bug
assignees: ''
---

## What happened

A clear description of the bug.

## What should have happened

What you expected to happen instead.

## Reproduction steps

1.
2.
3.

## Environment

- **Component**: server / extension / SDK (which one?)
- **Version**: (run `curl https://your-server/hhttps/info` or check extension popup)
- **Browser/OS**: (e.g. Chrome 130 on macOS 14.5)
- **Node.js version** (if relevant): `node -v`

## Logs

```
Paste relevant logs here. For the server: pm2 logs hhttps-v4 --lines 50
```

## Screenshots

If applicable.

## Have you tried

- [ ] Restarting the server (`pm2 restart hhttps-v4`)
- [ ] Hard browser reload (Ctrl+Shift+R)
- [ ] Clearing extension storage
- [ ] Checking [SECURITY.md](../SECURITY.md) — is this a security issue? If yes, **email instead**.
