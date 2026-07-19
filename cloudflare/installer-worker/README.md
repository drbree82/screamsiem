# ScreamSIEM installer Worker

This Worker serves the three bootstrap scripts (`monitored.sh`, `siem.sh`, and `demo.sh`) from the `installers/` directory and stores short-lived enrollment metadata in Workers KV. It stores only host metadata and the controller public key; no private key is uploaded.

The SIEM bootstrap supports headless Codex authentication. Select `codex` when prompted and it installs the Codex CLI when needed, then prints a one-time device-auth URL and code. Paste those into a browser on another computer to sign in with ChatGPT; the server itself does not need a browser.

First-time setup, from this directory:

```bash
npx --yes wrangler@latest login
npx --yes wrangler@latest kv namespace create ENROLLMENTS --update-config
npx --yes wrangler@latest deploy
```

For later changes, run only `npx --yes wrangler@latest deploy` from this directory. The `assets.directory` setting publishes the repository's `installers/` directory, so changes to any installer script are included automatically. The deployed `*.workers.dev` URL becomes the `SCREAMSIEM_INSTALLER_URL` used by the scripts. Test it with:

```bash
curl -fsSL https://YOUR-WORKER.workers.dev/monitored.sh | head
curl -fsSL https://YOUR-WORKER.workers.dev/siem.sh | head
curl -fsSL https://YOUR-WORKER.workers.dev/demo.sh | head
```

Current temporary deployment: `https://screamsiem-installer.flrgx-cxz.workers.dev`.

Use a long random enrollment code and retire the enrollment data after onboarding. The Worker is an enrollment relay, not a general-purpose remote shell or credential store.
