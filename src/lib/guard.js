/**
 * Two checks in front of every request, so a web page can't reach Broadcast Monitor through
 * the operator's own browser:
 *
 * - **Host check (DNS rebinding).** A page on some-site.com can point its own
 *   name at this computer's address and then talk to it as if it were
 *   same-origin. Real visitors use an IP address, `localhost`, a plain
 *   computer name (`stats-pc`) or a `.local` name, so anything else is refused.
 *   More names can be allowed with BM_ALLOWED_HOSTS (comma-separated).
 * - **Cross-site writes (CSRF).** Reading stays open to everyone (vMix,
 *   Apple Shortcuts and other tools read the status), but a request that
 *   changes something must not come from another site's page.
 */
import os from 'node:os';
import net from 'node:net';

const LAN_SUFFIX = /\.(local|lan|home|internal|localdomain|localhost|home\.arpa)$/;

export function hostName(hostHeader) {
  let h = String(hostHeader || '').trim().toLowerCase();
  if (h.startsWith('[')) h = h.slice(1, h.indexOf(']') > 0 ? h.indexOf(']') : undefined);
  else h = h.replace(/:\d*$/, '');
  return h.replace(/\.$/, '');
}

export function allowedHosts(env = process.env.BM_ALLOWED_HOSTS) {
  return String(env || '').split(',').map((s) => hostName(s)).filter(Boolean);
}

/** True when the Host header names this computer the way a LAN visitor would. */
export function hostAllowed(hostHeader, extra = allowedHosts()) {
  if (hostHeader === undefined || hostHeader === '') return true; // HTTP/1.0 tools send none
  const h = hostName(hostHeader);
  if (!h) return false;
  if (net.isIP(h)) return true;
  if (h === 'localhost' || !h.includes('.') || LAN_SUFFIX.test(h)) return true;
  if (h === os.hostname().toLowerCase()) return true;
  return extra.includes(h);
}

/** True when a browser says the request comes from another site's page. */
export function crossSite(req) {
  const origin = req.headers.origin;
  if (origin !== undefined) {
    if (origin === 'null') return true;
    try { return new URL(origin).host.toLowerCase() !== String(req.headers.host || '').toLowerCase(); } catch { return true; }
  }
  return req.headers['sec-fetch-site'] === 'cross-site';
}
