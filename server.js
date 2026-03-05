require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const cors    = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_KEY;
const URLSCAN_KEY    = process.env.URLSCAN_KEY || '';

// ─── Limpiar dominio ───────────────────────────────────────────────────────────
function cleanDomain(input) {
  return input.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0];
}

// ─── 1. WHOIS — whoisjsonapi.com (sin key) ────────────────────────────────────
async function getWhois(domain) {
  try {
    const res = await axios.get(`https://whoisjsonapi.com/v1/${domain}`, { timeout: 8000 });
    const d = res.data;
    return {
      ok: true,
      registrar:   d.registrar?.name || 'Desconocido',
      created:     d.creation_date?.[0]?.split('T')[0] || 'N/A',
      expires:     d.expiration_date?.[0]?.split('T')[0] || 'N/A',
      updated:     d.updated_date?.[0]?.split('T')[0] || 'N/A',
      status:      d.status?.[0] || 'N/A',
      nameservers: d.name_servers?.slice(0, 3) || [],
      country:     d.registrant_country || 'N/A',
      owner:       d.registrant_organization || d.registrant_name || 'Privado',
    };
  } catch (e) {
    return { ok: false, error: 'No se pudo obtener WHOIS' };
  }
}

// ─── 2. SSL — crt.sh (sin key) ────────────────────────────────────────────────
async function getSSL(domain) {
  try {
    const res = await axios.get(`https://crt.sh/?q=${domain}&output=json`, { timeout: 8000 });
    const certs = res.data;
    if (!certs || certs.length === 0) return { ok: false, error: 'Sin certificados' };
    const latest = certs.sort((a, b) => new Date(b.not_before) - new Date(a.not_before))[0];
    const expiry = new Date(latest.not_after);
    const now    = new Date();
    const days   = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
    return {
      ok: true,
      issuer:    latest.issuer_name?.split('O=')[1]?.split(',')[0]?.trim() || latest.issuer_name,
      issued:    latest.not_before?.split('T')[0],
      expires:   latest.not_after?.split('T')[0],
      daysLeft:  days,
      valid:     days > 0,
      commonName: latest.common_name,
      totalCerts: certs.length,
    };
  } catch (e) {
    return { ok: false, error: 'No se pudo verificar SSL' };
  }
}

// ─── 3. DNS / IPs — HackerTarget (sin key) ────────────────────────────────────
async function getDNS(domain) {
  try {
    const [dnsRes, ipRes] = await Promise.allSettled([
      axios.get(`https://api.hackertarget.com/dnslookup/?q=${domain}`, { timeout: 8000 }),
      axios.get(`https://api.hackertarget.com/hostsearch/?q=${domain}`, { timeout: 8000 }),
    ]);

    let records = [];
    if (dnsRes.status === 'fulfilled') {
      records = dnsRes.value.data.split('\n').filter(l => l.trim()).slice(0, 10);
    }

    let hosts = [];
    if (ipRes.status === 'fulfilled') {
      hosts = ipRes.value.data.split('\n').filter(l => l.trim()).slice(0, 6);
    }

    return { ok: true, records, hosts };
  } catch (e) {
    return { ok: false, error: 'No se pudo obtener DNS' };
  }
}

// ─── 4. Tecnologías — WhatCMS (sin key) ───────────────────────────────────────
async function getTech(domain) {
  try {
    const res = await axios.get(`https://whatcms.org/API/Tech?url=https://${domain}&key=free`, { timeout: 8000 });
    const techs = res.data?.results || [];
    return {
      ok: true,
      technologies: techs.slice(0, 10).map(t => ({
        name: t.name,
        category: t.categories?.[0] || 'General',
        version: t.version || null,
      }))
    };
  } catch (e) {
    return { ok: false, technologies: [] };
  }
}

// ─── 5. VirusTotal — Reputación y listas negras ───────────────────────────────
async function getVirusTotal(domain) {
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { 'x-apikey': VIRUSTOTAL_KEY },
      timeout: 10000,
    });
    const attr  = res.data.data.attributes;
    const stats = attr.last_analysis_stats;
    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;
    const harmless   = stats.harmless   || 0;
    const undetected = stats.undetected || 0;
    const total      = malicious + suspicious + harmless + undetected;
    const score      = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;

    const engines = res.data.data.attributes.last_analysis_results;
    const flagged = Object.entries(engines || {})
      .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
      .map(([name, v]) => ({ name, result: v.result }))
      .slice(0, 8);

    return {
      ok: true,
      score,
      malicious,
      suspicious,
      harmless,
      total,
      reputation: attr.reputation || 0,
      categories: Object.values(attr.categories || {}).slice(0, 4),
      flaggedBy:  flagged,
      tags:       attr.tags || [],
      popularity: attr.popularity_ranks || {},
    };
  } catch (e) {
    return { ok: false, error: 'Error consultando VirusTotal' };
  }
}

// ─── 6. Subdomains — HackerTarget (sin key) ───────────────────────────────────
async function getSubdomains(domain) {
  try {
    const res = await axios.get(`https://api.hackertarget.com/hostsearch/?q=${domain}`, { timeout: 8000 });
    const lines = res.data.split('\n').filter(l => l.trim() && !l.includes('error'));
    const subs  = lines.map(l => l.split(',')[0]).filter(Boolean).slice(0, 15);
    return { ok: true, subdomains: subs };
  } catch (e) {
    return { ok: false, subdomains: [] };
  }
}

// ─── 7. Screenshot — URLScan.io (con o sin key) ───────────────────────────────
async function getScreenshot(domain) {
  try {
    // Primero buscar si ya hay un scan reciente
    const search = await axios.get(
      `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=1`,
      { timeout: 8000, headers: URLSCAN_KEY ? { 'API-Key': URLSCAN_KEY } : {} }
    );
    const results = search.data?.results;
    if (results && results.length > 0) {
      const latest = results[0];
      const uuid   = latest.task?.uuid;
      const shot   = uuid ? `https://urlscan.io/screenshots/${uuid}.png` : null;
      const page   = latest.page || {};
      return {
        ok: true,
        screenshot: shot,
        scannedAt:  latest.task?.time?.split('T')[0] || 'N/A',
        country:    page.country || 'N/A',
        server:     page.server  || 'N/A',
        ip:         page.ip      || 'N/A',
        uuid,
      };
    }
    // Si no hay scan previo, enviar uno nuevo (solo si tenemos key)
    if (URLSCAN_KEY) {
      const submit = await axios.post('https://urlscan.io/api/v1/scan/',
        { url: `https://${domain}`, visibility: 'public' },
        { headers: { 'API-Key': URLSCAN_KEY, 'Content-Type': 'application/json' }, timeout: 8000 }
      );
      return { ok: true, screenshot: null, pending: true, uuid: submit.data?.uuid, scannedAt: 'Procesando...', country: 'N/A', server: 'N/A', ip: 'N/A' };
    }
    return { ok: false, error: 'Sin scans previos disponibles' };
  } catch (e) {
    return { ok: false, error: 'No se pudo obtener screenshot' };
  }
}

// ─── 8. Historial de cambios — detectar dominio nuevo/reciente ────────────────
function analyzeDomainAge(whois) {
  if (!whois.ok || !whois.created || whois.created === 'N/A') {
    return { ok: false, error: 'Sin datos de fecha' };
  }
  const created  = new Date(whois.created);
  const updated  = whois.updated !== 'N/A' ? new Date(whois.updated) : null;
  const expires  = whois.expires !== 'N/A' ? new Date(whois.expires)  : null;
  const now      = new Date();

  const ageMs    = now - created;
  const ageDays  = Math.floor(ageMs / (1000 * 60 * 60 * 24));
  const ageYears = (ageDays / 365).toFixed(1);

  // Detectar cambio reciente de propietario (updated muy reciente vs dominio viejo)
  let ownershipChange = false;
  let ownershipDays   = null;
  if (updated) {
    const updatedDays = Math.floor((now - updated) / (1000 * 60 * 60 * 24));
    ownershipDays = updatedDays;
    // Si el dominio es viejo (>1 año) pero fue actualizado hace <30 días = sospechoso
    if (ageDays > 365 && updatedDays < 30) ownershipChange = true;
  }

  // Cuántos días hasta expirar
  let expiresIn = null;
  if (expires) expiresIn = Math.floor((expires - now) / (1000 * 60 * 60 * 24));

  const isNew      = ageDays < 30;
  const isVeryNew  = ageDays < 7;
  const expiresSOON = expiresIn !== null && expiresIn < 60;

  const alerts = [];
  if (isVeryNew)      alerts.push({ level: 'critical', msg: `Dominio creado hace solo ${ageDays} días ⚠️` });
  else if (isNew)     alerts.push({ level: 'warning',  msg: `Dominio relativamente nuevo (${ageDays} días)` });
  if (ownershipChange) alerts.push({ level: 'critical', msg: `Posible cambio de propietario hace ${ownershipDays} días ⚠️` });
  if (expiresSOON)    alerts.push({ level: 'warning',  msg: `Dominio expira en ${expiresIn} días` });

  return {
    ok: true,
    ageDays,
    ageYears: parseFloat(ageYears),
    created:  whois.created,
    updated:  whois.updated,
    expires:  whois.expires,
    expiresIn,
    ownershipChange,
    ownershipDays,
    isNew,
    isVeryNew,
    alerts,
    trustLevel: isVeryNew || ownershipChange ? 'SOSPECHOSO' : isNew ? 'PRECAUCIÓN' : 'ESTABLECIDO',
  };
}

// ─── RUTA PRINCIPAL ───────────────────────────────────────────────────────────
app.post('/api/analyze', async (req, res) => {
  const { domain: raw } = req.body;
  if (!raw) return res.status(400).json({ error: 'Dominio requerido' });

  const domain = cleanDomain(raw);

  // Correr todas las APIs en paralelo
  const [whois, ssl, dns, tech, vt, subs, screenshot] = await Promise.all([
    getWhois(domain),
    getSSL(domain),
    getDNS(domain),
    getTech(domain),
    getVirusTotal(domain),
    getSubdomains(domain),
    getScreenshot(domain),
  ]);

  // Score de riesgo global
  let riskScore = 0;
  let riskFactors = [];

  if (vt.ok) {
    riskScore = vt.score;
    if (vt.malicious > 0)  riskFactors.push(`${vt.malicious} motores detectaron amenaza`);
    if (vt.suspicious > 0) riskFactors.push(`${vt.suspicious} motores lo marcaron sospechoso`);
  }
  if (ssl.ok) {
    if (!ssl.valid)          { riskScore += 20; riskFactors.push('Certificado SSL expirado'); }
    if (ssl.daysLeft < 30)   { riskScore += 10; riskFactors.push('SSL expira en menos de 30 días'); }
  } else {
    riskScore += 15; riskFactors.push('Sin certificado SSL');
  }
  if (whois.ok && whois.owner === 'Privado') riskFactors.push('Propietario oculto (privado)');

  const domainAge = analyzeDomainAge(whois);

  if (domainAge.ok) {
    if (domainAge.isVeryNew) { riskScore += 30; riskFactors.push(`Dominio creado hace solo ${domainAge.ageDays} días`); }
    else if (domainAge.isNew) { riskScore += 15; riskFactors.push(`Dominio nuevo (${domainAge.ageDays} días)`); }
    if (domainAge.ownershipChange) { riskScore += 25; riskFactors.push(`Posible cambio de propietario hace ${domainAge.ownershipDays} días`); }
  }

  riskScore = Math.min(100, riskScore);

  const riskLevel = riskScore >= 70 ? 'CRÍTICO' :
                    riskScore >= 40 ? 'MODERADO' :
                    riskScore >= 15 ? 'BAJO' : 'SEGURO';

  res.json({ domain, riskScore: Math.min(100,riskScore), riskLevel, riskFactors, whois, ssl, dns, tech, virustotal: vt, subdomains: subs, screenshot, domainAge });
});

app.listen(PORT, () => console.log(`DOMAINSPY running on port ${PORT}`));
