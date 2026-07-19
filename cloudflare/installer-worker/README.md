# ScreamSIEM installer Worker

This Worker serves the two bootstrap scripts from the `installers/` directory and stores short-lived enrollment metadata in Workers KV. It stores only host metadata and the controller public key; no private key is uploaded.

The SIEM bootstrap supports headless Codex authentication. Select `codex` when prompted and it installs the Codex CLI when needed, then prints a one-time device-auth URL and code. Paste those into a browser on another computer to sign in with ChatGPT; the server itself does not need a browser.

From this directory:

```bash
npx wrangler@latest kv namespace create ENROLLMENTS --update-config
npx wrangler@latest deploy
```

The namespace is already configured in `wrangler.jsonc`. The deployed `*.workers.dev` URL becomes the `SCREAMSIEM_INSTALLER_URL` used by both scripts. Test it with:

```bash
curl -fsSL https://YOUR-WORKER.workers.dev/monitored.sh | head
curl -fsSL https://YOUR-WORKER.workers.dev/siem.sh | head
```

Current temporary deployment: `https://screamsiem-installer.flrgx-cxz.workers.dev`.

Use a long random enrollment code and retire the enrollment data after onboarding. The Worker is an enrollment relay, not a general-purpose remote shell or credential store.
