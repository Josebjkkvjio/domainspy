# DOMAINSPY 🔍
### Domain Intelligence Platform

Analiza cualquier dominio y obtén: WHOIS, SSL, DNS, tecnologías, reputación y listas negras.

---

## APIs utilizadas

| API | Key requerida | Qué analiza |
|-----|--------------|-------------|
| VirusTotal | ✅ Sí | Reputación, listas negras, 70+ motores |
| whoisjsonapi.com | ❌ No | WHOIS completo |
| crt.sh | ❌ No | Certificado SSL |
| HackerTarget | ❌ No | DNS, subdominios |
| WhatCMS | ❌ No | Tecnologías del sitio |

---

## Cómo correr localmente

```bash
# 1. Instalar dependencias
npm install

# 2. Crear archivo .env con tu key
cp .env.example .env
# Edita .env y pon tu VIRUSTOTAL_KEY

# 3. Correr
npm start

# 4. Abrir en el browser
# http://localhost:3000
```

---

## Cómo subir a Railway

1. Sube los archivos a GitHub
2. En Railway → New Project → Deploy from GitHub
3. En Settings → Variables de entorno agrega:
   - `VIRUSTOTAL_KEY` = tu key de virustotal.com
4. Railway hace el deploy automático ✅

---

## Estructura del proyecto

```
domainspy/
├── index.html      ← UI completa
├── server.js       ← Backend Node.js
├── package.json    ← Dependencias
├── .env.example    ← Plantilla de variables
└── README.md       ← Este archivo
```

---

## Requerimientos del software

### Funcionales
- Analizar dominios ingresados por el usuario
- Mostrar información WHOIS (registrador, dueño, fechas)
- Verificar validez y días restantes del certificado SSL
- Consultar registros DNS y subdominios
- Detectar tecnologías usadas por el sitio
- Mostrar reputación en VirusTotal con detalle de motores
- Calcular score de riesgo global (0-100)

### No funcionales
- Respuesta en menos de 10 segundos
- APIs consultadas en paralelo (performance)
- API keys protegidas en el servidor (seguridad)
- Interfaz responsive para móvil y desktop
- Sin base de datos (stateless, fácil de desplegar)

---

## Diagrama ER (conceptual)

```
ANÁLISIS
├── dominio (PK)
├── fecha_consulta
├── score_riesgo
├── nivel_riesgo
│
├── WHOIS
│   ├── registrador
│   ├── propietario
│   ├── fecha_creacion
│   └── fecha_expiracion
│
├── SSL
│   ├── emisor
│   ├── fecha_emision
│   ├── fecha_expiracion
│   └── dias_restantes
│
├── DNS_RECORDS[]
│   └── registro
│
├── SUBDOMINIOS[]
│   └── subdominio
│
├── TECNOLOGIAS[]
│   ├── nombre
│   └── categoria
│
└── VIRUSTOTAL
    ├── score
    ├── malicious
    ├── suspicious
    ├── harmless
    └── MOTORES_FLAGGED[]
        ├── nombre_motor
        └── resultado
```
