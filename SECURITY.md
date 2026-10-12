# Security Policy

## Supported versions

Security fixes are released for the latest version only. Upgrade to the newest
release (or the `latest` Docker image) before reporting a problem.

## Reporting a vulnerability

Please do not open a public issue with the details of a vulnerability.

Report it privately through GitHub: on the repository's **Security** tab choose
**Report a vulnerability**
(<https://github.com/Rorqualx/flaresolverr-go/security/advisories/new>). If that
option is not available, open an issue that says only that you have a security
report and ask for a private contact; do not include details.

Useful reports include the version (`/health` shows it), the configuration that
matters (environment variables, with secrets removed), and the smallest request
that shows the problem.

## What to know before deploying

FlareSolverr drives a real browser to URLs chosen by whoever can reach its API.
Treat API access as the ability to make the host fetch arbitrary pages.

- **Do not expose the API to untrusted networks.** Bind it to localhost or a
  private network, and set `API_KEY_ENABLED=true` with an `API_KEY` if anything
  other than your own services can reach it.
- **The browser sandbox is off by default.** Chromium is launched with
  `--no-sandbox`, because its sandbox needs kernel features (user namespaces or
  a permissive seccomp profile) that default container runtimes do not grant. A
  renderer compromise is therefore contained by the container, not by Chromium.
  Run the container as shipped (non-root user, `no-new-privileges`), do not add
  capabilities, and do not mount anything it does not need. `BROWSER_SANDBOX` is
  an opt-in setting that turns the sandbox on for hosts that support it.
- **Target URLs are checked, but the browser is not network-isolated.** A URL
  that points at a private or metadata address is refused, and the page's final
  URL is checked again before anything is returned. The browser still follows
  redirects and loads subresources on its own, so a page can make it send
  requests to addresses the host can reach. If the host can reach internal
  services, restrict the container's egress at the network level as well.

## Past audits

Earlier audit reports are kept in [docs/audits/](docs/audits/) for reference.
They describe old versions and are superseded by the changelog.
