// Defanging = making URLs / domains NON-clickable before they are shown (threat-intel practice):
// https://bad.example.com/x -> hxxps://bad[.]example[.]com/x. The C2 read APIs already defang;
// POST /api/v1/analyze does not (it is an API answer, not a display), so the UI defangs it here.
// Idempotent: defanging twice changes nothing. Mirrors services/c2-.../utils/defang.py.

const SCHEMES = { http: 'hxxp', https: 'hxxps', ftp: 'fxp', ftps: 'fxps' }
const URL_IN_TEXT = /\b([a-z][a-z0-9+.-]*):\/\/([^\s/?#"'<>\\]+)/gi
// A bare domain: labels + an alphabetic ending. Endings are checked below so that rule ids
// (behavior.clickfix) and file names (config.yaml) stay readable.
const DOMAIN_IN_TEXT = /(?<![\w.[@/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z][a-z0-9-]{1,62}))(?![\w[-])/gi
const COMMON_TLDS = new Set(
  ('com net org info biz xyz top site online shop store app dev io co me live click link club icu vip cc tk ml ga cf gq ' +
    'pw buzz guru ai win bid loan work website space tech fun pro mobi asia cloud email services support help ' +
    'finance money bank cash exchange trade crypto best today world life net lk invalid example test local onion').split(' '),
)

function looksLikeDomain(tld) {
  const ending = tld.toLowerCase()
  return COMMON_TLDS.has(ending) || /^[a-z]{2}$/.test(ending) || ending.startsWith('xn--')
}

export function defangHost(host) {
  if (!host) return host
  return String(host).replaceAll('[.]', '.').replaceAll('.', '[.]')
}

export function defangText(text) {
  if (text === null || text === undefined || text === '') return text
  return String(text)
    .replace(URL_IN_TEXT, (_, scheme, host) => `${SCHEMES[scheme.toLowerCase()] || scheme}://${defangHost(host)}`)
    .replace(DOMAIN_IN_TEXT, (match, domain, tld) => (looksLikeDomain(tld) ? defangHost(domain) : match))
}

export function defangUrl(url) {
  if (!url) return url
  const text = String(url).trim()
  const match = /^(https?):\/\/([^/?#]*)(.*)$/i.exec(text)
  if (!match) return defangText(text)
  const [, scheme, host, rest] = match
  return `${SCHEMES[scheme.toLowerCase()]}://${defangHost(host)}${rest}`
}
