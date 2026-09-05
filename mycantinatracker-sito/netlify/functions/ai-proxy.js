// ai-proxy.js
//
// Funzione server-side (Netlify Function): riceve le richieste dal sito,
// verifica che chi chiama abbia fatto login con Google/Firebase, e solo
// in quel caso contatta l'API di Claude usando la chiave segreta tenuta
// nelle variabili d'ambiente di Netlify (mai nel codice del sito).
//
// Non richiede nessuna libreria da installare (nessun "npm install"):
// usa solo moduli integrati in Node.js, cosi' funziona anche pubblicando
// con il semplice trascina-e-rilascia.
//
// IMPORTANTE — configurazione richiesta su Netlify prima di funzionare:
// 1. "Site configuration" -> "Environment variables" -> aggiungi una
//    variabile chiamata ANTHROPIC_API_KEY con la tua chiave API Anthropic
//    (da https://console.anthropic.com).
// 2. Se in futuro cambi progetto Firebase, aggiorna FIREBASE_PROJECT_ID
//    qui sotto con il nuovo project id.

const FIREBASE_PROJECT_ID = 'mycantinatracker';

const crypto = require('crypto');

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}

let cachedCerts = null;
let cachedCertsExpiry = 0;

async function getGoogleCerts() {
  const now = Date.now();
  if (cachedCerts && now < cachedCertsExpiry) return cachedCerts;
  const res = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
  const certs = await res.json();
  cachedCerts = certs;
  cachedCertsExpiry = now + 60 * 60 * 1000; // tieni le chiavi in cache per un'ora
  return certs;
}

// Verifica un token di login Firebase senza usare firebase-admin:
// controlla firma, scadenza, progetto di provenienza.
async function verifyFirebaseIdToken(idToken) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Token malformato');

  const header = JSON.parse(base64UrlDecode(parts[0]));
  const payload = JSON.parse(base64UrlDecode(parts[1]));

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) throw new Error('Token scaduto');
  if (payload.aud !== FIREBASE_PROJECT_ID) throw new Error('Audience non valida');
  if (payload.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`) throw new Error('Issuer non valido');

  const certs = await getGoogleCerts();
  const cert = certs[header.kid];
  if (!cert) throw new Error('Chiave di verifica non trovata');

  const signedData = parts[0] + '.' + parts[1];
  const signature = Buffer.from(parts[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64');

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(signedData);
  verifier.end();
  if (!verifier.verify(cert, signature)) throw new Error('Firma non valida');

  return payload;
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Metodo non consentito' }) };
  }

  const authHeader = event.headers.authorization || event.headers.Authorization || '';
  const idToken = authHeader.replace(/^Bearer\s+/i, '');
  if (!idToken) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Accesso richiesto' }) };
  }

  try {
    await verifyFirebaseIdToken(idToken);
  } catch (err) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Sessione non valida, rifai il login e riprova.' }) };
  }

  if (!process.env.ANTHROPIC_API_KEY) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Chiave API non configurata sul server.' }) };
  }

  let payload;
  try {
    payload = JSON.parse(event.body);
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Richiesta non valida' }) };
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: payload.max_tokens || 1000,
        messages: payload.messages
      })
    });
    const data = await response.json();
    return {
      statusCode: response.status,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    };
  } catch (err) {
    return { statusCode: 502, body: JSON.stringify({ error: 'Errore nel contattare il servizio IA' }) };
  }
};
