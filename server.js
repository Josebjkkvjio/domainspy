require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const cors    = require('cors');
const net     = require('net');
const https   = require('https');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_KEY;
const URLSCAN_KEY    = process.env.URLSCAN_KEY || '';

function cleanDomain(input) {
  return input.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0];
}

// ─── 1. WHOIS — 3 intentos en cascada ────────────────────────────────────────
async function getWhois(domain) {
  // Intento 1: whoisjsonapi
  try {
    const res = await axios.get(`https://whoisjsonapi.com/v1/${domain}`, { timeout: 8000 });
    const d = res.data;
    if (d && (d.creation_date || d.registrar)) {
      return {
        ok: true, source: 'WHOIS',
        registrar:   d.registrar?.name || 'Desconocido',
        created:     d.creation_date?.[0]?.split('T')[0] || 'N/A',
        expires:     d.expiration_date?.[0]?.split('T')[0] || 'N/A',
        updated:     d.updated_date?.[0]?.split('T')[0] || 'N/A',
        status:      d.status?.[0] || 'N/A',
        nameservers: d.name_servers?.slice(0, 3) || [],
        country:     d.registrant_country || 'N/A',
        owner:       d.registrant_organization || d.registrant_name || 'Privado',
      };
    }
  } catch (_) {}

  // Intento 2: RDAP
  try {
    const r = (await axios.get(`https://rdap.org/domain/${domain}`, { timeout: 8000 })).data;
    const getDate = (type) => r.events?.find(e => e.eventAction === type)?.eventDate?.split('T')[0] || 'N/A';
    const ns  = r.nameservers?.map(n => n.ldhName?.toLowerCase()).filter(Boolean).slice(0, 3) || [];
    const reg = r.entities?.find(e => e.roles?.includes('registrar'))?.vcardArray?.[1]?.find(v => v[0]==='fn')?.[3] || 'Privado';
    const own = r.entities?.find(e => e.roles?.includes('registrant'))?.vcardArray?.[1]?.find(v => v[0]==='fn')?.[3] || 'Privado';
    if (getDate('registration') !== 'N/A' || reg !== 'Privado') {
      return {
        ok: true, source: 'RDAP',
        registrar: reg, owner: own,
        created: getDate('registration'),
        expires: getDate('expiration'),
        updated: getDate('last changed'),
        status:  r.status?.[0] || 'N/A',
        nameservers: ns, country: 'N/A',
      };
    }
  } catch (_) {}

  // Intento 3: RDAP por TLD
  try {
    const tld = domain.split('.').pop();
    const services = (await axios.get('https://data.iana.org/rdap/dns.json', { timeout: 5000 })).data?.services || [];
    let rdapUrl = null;
    for (const [tlds, urls] of services) { if (tlds.includes(tld)) { rdapUrl = urls[0]; break; } }
    if (rdapUrl) {
      const r = (await axios.get(`${rdapUrl}domain/${domain}`, { timeout: 8000 })).data;
      const getDate = (type) => r.events?.find(e => e.eventAction === type)?.eventDate?.split('T')[0] || 'N/A';
      return {
        ok: true, source: 'RDAP/IANA',
        registrar: r.entities?.find(e => e.roles?.includes('registrar'))?.vcardArray?.[1]?.find(v => v[0]==='fn')?.[3] || 'Privado',
        owner: 'Privado',
        created: getDate('registration'), expires: getDate('expiration'), updated: getDate('last changed'),
        status: r.status?.[0] || 'N/A',
        nameservers: r.nameservers?.map(n => n.ldhName?.toLowerCase()).filter(Boolean).slice(0,3) || [],
        country: 'N/A',
      };
    }
  } catch (_) {}

  return { ok: false, error: 'WHOIS protegido' };
}

// ─── 2. SSL — crt.sh + conexión directa ──────────────────────────────────────
async function getSSL(domain) {
  try {
    const certs = (await axios.get(`https://crt.sh/?q=${domain}&output=json`, { timeout: 10000 })).data;
    if (certs?.length > 0) {
      const latest = certs.sort((a,b) => new Date(b.not_before)-new Date(a.not_before))[0];
      const days = Math.floor((new Date(latest.not_after)-new Date())/(1000*60*60*24));
      return {
        ok: true, source: 'crt.sh',
        issuer: latest.issuer_name?.split('O=')[1]?.split(',')[0]?.trim() || latest.issuer_name,
        issued: latest.not_before?.split('T')[0],
        expires: latest.not_after?.split('T')[0],
        daysLeft: days, valid: days > 0,
        commonName: latest.common_name, totalCerts: certs.length,
      };
    }
  } catch (_) {}

  // Respaldo: conexión HTTPS directa
  try {
    const cert = await new Promise((resolve, reject) => {
      const req = https.request({ host: domain, port: 443, method: 'HEAD', rejectUnauthorized: false, timeout: 8000 }, res => {
        const c = res.socket?.getPeerCertificate();
        c?.valid_to ? resolve(c) : reject(new Error('no cert'));
      });
      req.on('error', reject);
      req.on('timeout', () => reject(new Error('timeout')));
      req.end();
    });
    const days = Math.floor((new Date(cert.valid_to)-new Date())/(1000*60*60*24));
    return {
      ok: true, source: 'Conexión directa',
      issuer: cert.issuer?.O || cert.issuer?.CN || 'Desconocido',
      issued: new Date(cert.valid_from).toISOString().split('T')[0],
      expires: new Date(cert.valid_to).toISOString().split('T')[0],
      daysLeft: days, valid: days > 0,
      commonName: cert.subject?.CN || domain, totalCerts: 1,
    };
  } catch (_) {}

  return { ok: false, error: 'No se pudo verificar SSL' };
}

// ─── 3. DNS ───────────────────────────────────────────────────────────────────
async function getDNS(domain) {
  try {
    const [dnsRes, ipRes] = await Promise.allSettled([
      axios.get(`https://api.hackertarget.com/dnslookup/?q=${domain}`, { timeout: 8000 }),
      axios.get(`https://api.hackertarget.com/hostsearch/?q=${domain}`, { timeout: 8000 }),
    ]);
    return {
      ok: true,
      records: dnsRes.status==='fulfilled' ? dnsRes.value.data.split('\n').filter(l=>l.trim()).slice(0,10) : [],
      hosts:   ipRes.status==='fulfilled'  ? ipRes.value.data.split('\n').filter(l=>l.trim()).slice(0,6)   : [],
    };
  } catch (e) { return { ok: false, error: 'No se pudo obtener DNS' }; }
}

// ─── 4. Tecnologías — WhatCMS + detección manual ─────────────────────────────
async function getTech(domain) {
  try {
    const techs = (await axios.get(`https://whatcms.org/API/Tech?url=https://${domain}&key=free`, { timeout: 8000 })).data?.results || [];
    if (techs.length > 0) return {
      ok: true, source: 'WhatCMS',
      technologies: techs.slice(0,10).map(t => ({ name: t.name, category: t.categories?.[0]||'General', version: t.version||null }))
    };
  } catch (_) {}

  // Detección manual por headers + HTML
  try {
    const res = await axios.get(`https://${domain}`, {
      timeout: 9000, maxRedirects: 5, validateStatus: ()=>true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36' },
    });
    const html = res.data?.toString() || '';
    const h    = res.headers || {};
    const techs = [];

    const server  = h['server'] || '';
    const powered = h['x-powered-by'] || '';
    if (server)  techs.push({ name: server,  category: 'Servidor Web',       version: null });
    if (powered) techs.push({ name: powered, category: 'Lenguaje/Framework', version: null });

    const detectors = [
      [/wp-content|wp-includes|wordpress/i,       'WordPress',       'CMS'],
      [/drupal/i,                                  'Drupal',          'CMS'],
      [/joomla/i,                                  'Joomla',          'CMS'],
      [/squarespace\.com/i,                        'Squarespace',     'CMS'],
      [/ghost\.org|content\/themes\/ghost/i,       'Ghost',           'CMS'],
      [/__next|_next\/static/i,                    'Next.js',         'Framework'],
      [/nuxt|__nuxt/i,                             'Nuxt.js',         'Framework'],
      [/react[-.]development|react[-.]production/i,'React',           'Framework'],
      [/angular\.min\.js|ng-version/i,             'Angular',         'Framework'],
      [/vue\.min\.js|vue\.runtime/i,               'Vue.js',          'Framework'],
      [/laravel|laravel_session/i,                 'Laravel',         'Framework'],
      [/django|csrftoken/i,                        'Django',          'Framework'],
      [/jquery[-.][\d]/i,                          'jQuery',          'Librería JS'],
      [/bootstrap\.min\.(css|js)/i,                'Bootstrap',       'CSS Framework'],
      [/tailwindcss|class="[^"]*\btw-/i,           'Tailwind CSS',    'CSS Framework'],
      [/gtag\(|googletagmanager\.com/i,            'Google Analytics','Analytics'],
      [/fbq\(|connect\.facebook\.net/i,            'Facebook Pixel',  'Marketing'],
      [/cdn\.cloudflare\.com|__cf_bm|cf-ray/i,     'Cloudflare',      'CDN/Seguridad'],
      [/fastly/i,                                  'Fastly',          'CDN'],
      [/akamai/i,                                  'Akamai',          'CDN'],
      [/cdnjs\.cloudflare\.com/i,                  'Cloudflare CDN',  'CDN'],
      [/recaptcha/i,                               'reCAPTCHA',       'Seguridad'],
      [/stripe\.com\/v3/i,                         'Stripe',          'Pagos'],
      [/paypal\.com\/sdk/i,                        'PayPal',          'Pagos'],
      [/intercom/i,                                'Intercom',        'Soporte'],
      [/zendesk/i,                                 'Zendesk',         'Soporte'],
      [/x-shopify|shopify\.com/i,                  'Shopify',         'E-Commerce'],
      [/woocommerce/i,                             'WooCommerce',     'E-Commerce'],
      [/x-wix|wix\.com/i,                          'Wix',             'CMS'],
      [/webflow/i,                                 'Webflow',         'CMS'],
    ];
    for (const [rx, name, cat] of detectors) {
      if (rx.test(html) && !techs.find(t=>t.name===name))
        techs.push({ name, category: cat, version: null });
    }
    // Detectar también en headers como cf-ray
    if ((h['cf-ray'] || h['server']==='cloudflare') && !techs.find(t=>t.name==='Cloudflare'))
      techs.push({ name: 'Cloudflare', category: 'CDN/Seguridad', version: null });

    if (techs.length > 0) return { ok: true, technologies: techs.slice(0,12), source: 'Detección automática' };
  } catch (_) {}

  return { ok: true, technologies: [], source: 'N/A' };
}

// ─── 5. VirusTotal ────────────────────────────────────────────────────────────
async function getVirusTotal(domain) {
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { 'x-apikey': VIRUSTOTAL_KEY }, timeout: 10000,
    });
    const attr  = res.data.data.attributes;
    const stats = attr.last_analysis_stats;
    const malicious = stats.malicious||0, suspicious = stats.suspicious||0;
    const harmless  = stats.harmless||0,  undetected = stats.undetected||0;
    const total = malicious+suspicious+harmless+undetected;
    return {
      ok: true,
      score:      total>0 ? Math.round(((malicious+suspicious)/total)*100) : 0,
      malicious, suspicious, harmless, total,
      reputation: attr.reputation||0,
      categories: Object.values(attr.categories||{}).slice(0,4),
      flaggedBy:  Object.entries(attr.last_analysis_results||{})
                    .filter(([,v])=>v.category==='malicious'||v.category==='suspicious')
                    .map(([name,v])=>({name, result:v.result})).slice(0,8),
      tags:       attr.tags||[],
      popularity: attr.popularity_ranks||{},
    };
  } catch (e) { return { ok: false, error: 'Error consultando VirusTotal' }; }
}

// ─── 6. Subdominios ───────────────────────────────────────────────────────────
async function getSubdomains(domain) {
  try {
    const res  = await axios.get(`https://api.hackertarget.com/hostsearch/?q=${domain}`, { timeout: 8000 });
    const subs = res.data.split('\n').filter(l=>l.trim()&&!l.includes('error')).map(l=>l.split(',')[0]).filter(Boolean).slice(0,15);
    return { ok: true, subdomains: subs };
  } catch (e) { return { ok: false, subdomains: [] }; }
}

// ─── 7. Screenshot — URLScan.io ───────────────────────────────────────────────
async function getScreenshot(domain) {
  try {
    const results = (await axios.get(`https://urlscan.io/api/v1/search/?q=page.domain:${domain}&size=5`,
      { timeout: 8000, headers: URLSCAN_KEY ? { 'API-Key': URLSCAN_KEY } : {} }
    )).data?.results;
    if (results?.length > 0) {
      const exact  = results.find(r => r.page?.domain===domain || r.task?.url?.replace(/^https?:\/\/(www\.)?/,'').split('/')[0]===domain);
      const latest = exact || results[0];
      const uuid   = latest.task?.uuid;
      return {
        ok: true,
        screenshot: uuid ? `https://urlscan.io/screenshots/${uuid}.png` : null,
        scannedAt:  latest.task?.time?.split('T')[0]||'N/A',
        country:    latest.page?.country||'N/A',
        server:     latest.page?.server||'N/A',
        ip:         latest.page?.ip||'N/A',
        uuid,
      };
    }
    if (URLSCAN_KEY) {
      const submit = await axios.post('https://urlscan.io/api/v1/scan/',
        { url:`https://${domain}`, visibility:'public' },
        { headers:{'API-Key':URLSCAN_KEY,'Content-Type':'application/json'}, timeout:8000 }
      );
      return { ok:true, screenshot:null, pending:true, uuid:submit.data?.uuid, scannedAt:'Procesando...', country:'N/A', server:'N/A', ip:'N/A' };
    }
    return { ok: false, error: 'Sin scans previos disponibles' };
  } catch (e) { return { ok: false, error: 'No se pudo obtener screenshot' }; }
}

// ─── 8. Edad del dominio ──────────────────────────────────────────────────────
function analyzeDomainAge(whois) {
  if (!whois.ok || !whois.created || whois.created==='N/A') return { ok: false };
  const created = new Date(whois.created);
  const updated = whois.updated!=='N/A' ? new Date(whois.updated) : null;
  const expires = whois.expires!=='N/A' ? new Date(whois.expires)  : null;
  const now     = new Date();
  const ageDays = Math.floor((now-created)/(1000*60*60*24));
  let ownershipChange=false, ownershipDays=null, expiresIn=null;
  if (updated) { ownershipDays=Math.floor((now-updated)/(1000*60*60*24)); if(ageDays>365&&ownershipDays<30) ownershipChange=true; }
  if (expires) expiresIn=Math.floor((expires-now)/(1000*60*60*24));
  const isNew=ageDays<30, isVeryNew=ageDays<7;
  const alerts=[];
  if (isVeryNew)       alerts.push({level:'critical',msg:`Dominio creado hace solo ${ageDays} días ⚠️`});
  else if (isNew)      alerts.push({level:'warning', msg:`Dominio nuevo (${ageDays} días)`});
  if (ownershipChange) alerts.push({level:'critical',msg:`Posible cambio de propietario hace ${ownershipDays} días ⚠️`});
  if (expiresIn!==null&&expiresIn<60) alerts.push({level:'warning',msg:`Dominio expira en ${expiresIn} días`});
  return {
    ok:true, ageDays, ageYears:parseFloat((ageDays/365).toFixed(1)),
    created:whois.created, updated:whois.updated, expires:whois.expires,
    expiresIn, ownershipChange, ownershipDays, isNew, isVeryNew, alerts,
    trustLevel: isVeryNew||ownershipChange?'SOSPECHOSO':isNew?'PRECAUCIÓN':'ESTABLECIDO',
  };
}

// ─── 9. Wayback Machine ───────────────────────────────────────────────────────
async function getWayback(domain) {
  try {
    const snap = (await axios.get(`https://archive.org/wayback/available?url=${domain}`, { timeout: 7000 })).data?.archived_snapshots?.closest;
    if (!snap?.available) return { ok: false };
    const cdx = (await axios.get(`https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=1&fl=timestamp&filter=statuscode:200`, { timeout: 7000 })).data;
    let firstSeen = null;
    if (cdx?.length>1) { const ts=cdx[1][0]; firstSeen=`${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}`; }
    const ts = snap.timestamp;
    return {
      ok: true, firstSeen,
      latestSnapshot: `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}`,
      latestUrl: snap.url,
      yearsOnline: firstSeen ? Math.floor((new Date()-new Date(firstSeen))/(1000*60*60*24*365)) : null,
    };
  } catch (_) { return { ok: false }; }
}

// ─── 10. Geo IP ───────────────────────────────────────────────────────────────
async function getGeoIP(domain) {
  try {
    const d = (await axios.get(`http://ip-api.com/json/${domain}?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon,timezone,proxy,hosting`, { timeout: 6000 })).data;
    if (d.status!=='success') return { ok: false };
    return { ok:true, country:d.country, countryCode:d.countryCode, region:d.regionName, city:d.city, isp:d.isp, org:d.org, as:d.as, lat:d.lat, lon:d.lon, timezone:d.timezone, isProxy:d.proxy, isHosting:d.hosting };
  } catch (e) { return { ok: false }; }
}

// ─── 11. Security Headers ─────────────────────────────────────────────────────
async function getSecurityHeaders(domain) {
  try {
    const h = (await axios.get(`https://${domain}`, { timeout: 8000, maxRedirects:5, validateStatus:()=>true, headers:{'User-Agent':'Mozilla/5.0 (compatible; DomainSpy/1.0)'} })).headers;
    const checks = {
      'Strict-Transport-Security': !!h['strict-transport-security'],
      'Content-Security-Policy':   !!h['content-security-policy'],
      'X-Frame-Options':           !!h['x-frame-options'],
      'X-Content-Type-Options':    !!h['x-content-type-options'],
      'Referrer-Policy':           !!h['referrer-policy'],
      'Permissions-Policy':        !!h['permissions-policy'],
    };
    const score = Object.values(checks).filter(Boolean).length;
    return { ok:true, headers:checks, score, maxScore:6, grade:score>=5?'A':score>=3?'B':score>=1?'C':'F', server:h['server']||null, poweredBy:h['x-powered-by']||null, statusCode:200 };
  } catch (e) { return { ok: false }; }
}

// ─── 12. Disponibilidad ───────────────────────────────────────────────────────
async function checkAvailability(domain) {
  const start = Date.now();
  try {
    const res = await axios.get(`https://${domain}`, { timeout:10000, maxRedirects:5, validateStatus:()=>true, headers:{'User-Agent':'Mozilla/5.0 (compatible; DomainSpy/1.0)'} });
    const rt = Date.now()-start;
    return { ok:true, online:true, statusCode:res.status, responseTime:rt, speed:rt<500?'Rápido':rt<1500?'Normal':'Lento' };
  } catch (e) { return { ok:true, online:false, responseTime:Date.now()-start, speed:'Offline' }; }
}

// ─── 13. Port Scanner ─────────────────────────────────────────────────────────
async function scanPorts(domain) {
  const ports = [
    { port:21,   name:'FTP',    risk:'alto',   desc:'Transferencia de archivos sin cifrar' },
    { port:22,   name:'SSH',    risk:'medio',  desc:'Acceso remoto seguro' },
    { port:23,   name:'Telnet', risk:'crítico',desc:'Acceso remoto SIN cifrar' },
    { port:25,   name:'SMTP',   risk:'medio',  desc:'Servidor de correo saliente' },
    { port:53,   name:'DNS',    risk:'info',   desc:'Resolución de nombres' },
    { port:80,   name:'HTTP',   risk:'info',   desc:'Web sin cifrar' },
    { port:443,  name:'HTTPS',  risk:'info',   desc:'Web cifrada (SSL/TLS)' },
    { port:445,  name:'SMB',    risk:'crítico',desc:'Compartir archivos Windows' },
    { port:3306, name:'MySQL',  risk:'crítico',desc:'Base de datos expuesta' },
    { port:3389, name:'RDP',    risk:'crítico',desc:'Escritorio remoto Windows' },
    { port:5432, name:'PostgreSQL', risk:'crítico', desc:'Base de datos expuesta' },
    { port:6379, name:'Redis',  risk:'crítico',desc:'Base de datos en memoria expuesta' },
    { port:8080, name:'HTTP-Alt',risk:'medio', desc:'Puerto web alternativo' },
    { port:8443, name:'HTTPS-Alt',risk:'medio',desc:'Puerto HTTPS alternativo' },
  ];

  const scanPort = (host, port) => new Promise(resolve => {
    const socket = new net.Socket();
    const timeout = 1500;
    socket.setTimeout(timeout);
    socket.on('connect', () => { socket.destroy(); resolve(true); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('error',   () => { socket.destroy(); resolve(false); });
    socket.connect(port, host);
  });

  const results = await Promise.all(
    ports.map(async p => ({
      ...p,
      open: await scanPort(domain, p.port),
    }))
  );

  const openPorts   = results.filter(p => p.open);
  const criticalOpen = openPorts.filter(p => p.risk === 'crítico');

  return {
    ok: true,
    ports: results,
    openCount: openPorts.length,
    criticalCount: criticalOpen.length,
    summary: criticalOpen.length > 0
      ? `⚠️ ${criticalOpen.length} puerto(s) crítico(s) expuesto(s)`
      : openPorts.length > 0
        ? `${openPorts.length} puerto(s) abierto(s), sin riesgo crítico`
        : 'Sin puertos peligrosos expuestos',
  };
}

// ─── RUTA PRINCIPAL ───────────────────────────────────────────────────────────
app.post('/api/analyze', async (req, res) => {
  const { domain: raw } = req.body;
  if (!raw) return res.status(400).json({ error: 'Dominio requerido' });
  const domain = cleanDomain(raw);

  const [whois, ssl, dns, tech, vt, subs, screenshot, geo, secHeaders, availability, wayback, ports] = await Promise.all([
    getWhois(domain), getSSL(domain), getDNS(domain), getTech(domain),
    getVirusTotal(domain), getSubdomains(domain), getScreenshot(domain),
    getGeoIP(domain), getSecurityHeaders(domain), checkAvailability(domain),
    getWayback(domain), scanPorts(domain),
  ]);

  let riskScore = 0, riskFactors = [];
  if (vt.ok) {
    riskScore = vt.score;
    if (vt.malicious>0)  riskFactors.push(`${vt.malicious} motores detectaron amenaza`);
    if (vt.suspicious>0) riskFactors.push(`${vt.suspicious} motores lo marcaron sospechoso`);
  }
  if (ssl.ok) {
    if (!ssl.valid)        { riskScore+=20; riskFactors.push('Certificado SSL expirado'); }
    if (ssl.daysLeft<30)   { riskScore+=10; riskFactors.push('SSL expira en menos de 30 días'); }
  } else { riskScore+=15; riskFactors.push('Sin certificado SSL'); }

  const domainAge = analyzeDomainAge(whois);
  if (domainAge.ok) {
    if (domainAge.isVeryNew)       { riskScore+=30; riskFactors.push(`Dominio creado hace solo ${domainAge.ageDays} días`); }
    else if (domainAge.isNew)      { riskScore+=15; riskFactors.push(`Dominio nuevo (${domainAge.ageDays} días)`); }
    if (domainAge.ownershipChange) { riskScore+=25; riskFactors.push(`Posible cambio de propietario hace ${domainAge.ownershipDays} días`); }
  }
  if (secHeaders.ok && secHeaders.grade==='F') { riskScore+=10; riskFactors.push('Sin headers de seguridad HTTP'); }
  if (geo.ok && geo.isProxy) { riskScore+=15; riskFactors.push('IP asociada a proxy/VPN'); }
  if (ports.ok && ports.criticalCount>0) { riskScore+=ports.criticalCount*10; riskFactors.push(`${ports.criticalCount} puerto(s) crítico(s) expuesto(s)`); }

  riskScore = Math.min(100, riskScore);
  const riskLevel = riskScore>=70?'CRÍTICO':riskScore>=40?'MODERADO':riskScore>=15?'BAJO':'SEGURO';

  res.json({ domain, riskScore, riskLevel, riskFactors, whois, ssl, dns, tech, virustotal:vt, subdomains:subs, screenshot, domainAge, geo, securityHeaders:secHeaders, availability, wayback, ports });
});

app.listen(PORT, () => console.log(`DOMAINSPY running on port ${PORT}`));
