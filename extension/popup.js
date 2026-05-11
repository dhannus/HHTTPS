/**
 * HHTTPS Extension Popup Script (v1.1.0)
 * Compatible with HHTTPS protocol v0.4.1 — supports all 15 roles.
 */

const ROLE_DATA = {
  citizen: {
    icon: '🧑', name: 'Bürger',
    level: 'Grundverifikation',
    privs: ['Verifizierter Mensch im digitalen Raum', 'Schutz vor Deepfake-Missbrauch', 'Anonyme Kommunikation mit HHTTPS-Kennzeichnung']
  },
  journalist: {
    icon: '📰', name: 'Journalist',
    level: 'Presseausweis · E-Mail',
    privs: ['Zugang zu HHTTPS-Pressebereichen', 'Verifizierte Quellenangabe', 'Schutz vor KI-Identitätsmissbrauch']
  },
  student: {
    icon: '🎓', name: 'Schüler / Student',
    level: 'Bildungs-E-Mail · Matrikelnummer',
    privs: ['Verifizierte Online-Prüfungen', 'Schutz vor KI-generierten Antworten von Peers', 'Bildungsplattformen-Zugang']
  },
  teacher: {
    icon: '👨‍🏫', name: 'Lehrer / Pädagoge',
    level: 'Schul-E-Mail · Lehrer-ID',
    privs: ['Verifizierte Eltern-Lehrer-Kommunikation', 'Authentische Bekanntmachungen', 'Schutz vor Fake-Lehrer-Identitäten']
  },
  researcher: {
    icon: '🔬', name: 'Wissenschaftler',
    level: 'ORCID · Uni-E-Mail',
    privs: ['Verifizierte Autorenschaft', 'HHTTPS Peer-Review', 'Schutz wissenschaftlicher Reputation']
  },
  creative: {
    icon: '🎭', name: 'Kreativschaffender',
    level: 'Verbandsmitglied',
    privs: ['Stimm-/Gesichtsschutz vor KI-Klonen', 'Nachweis menschlicher Urheberschaft', 'Verifizierte Identität in Kreativplattformen']
  },
  developer: {
    icon: '💻', name: 'Entwickler',
    level: 'GitHub · E-Mail',
    privs: ['API-Zugang mit erhöhten Rate-Limits', 'Zugang zu HHTTPS-Testumgebungen', 'Verifizierte Code-Autorenschaft']
  },
  medical_professional: {
    icon: '🩺', name: 'Arzt / Medizinerin',
    level: 'Approbation · Klinik-E-Mail',
    privs: ['Verifizierte medizinische Auskünfte', 'Schutz vor Fake-Ärzten in Patientenforen', 'Authentische Telemedizin']
  },
  caregiver: {
    icon: '🤝', name: 'Pflegekraft',
    level: 'Pflegekammer · E-Mail',
    privs: ['Verifizierte Patientenkommunikation', 'Schutz vor Identitätsmissbrauch', 'Authentische Pflegeberatung']
  },
  lawyer: {
    icon: '⚖️', name: 'Anwalt / Anwältin',
    level: 'RAK-Eintrag · Kanzlei-E-Mail',
    privs: ['Verifizierte Rechtsberatung digital', 'Schutz vor KI-Pseudo-Rechtsberatung', 'Authentische Mandanten-Kommunikation']
  },
  notary: {
    icon: '📜', name: 'Notar',
    level: 'Notarkammer-Eintrag',
    privs: ['Verifizierte notarielle Auskünfte', 'HHTTPS bei digitaler Beurkundung', 'Höchste Vertrauensstufe']
  },
  civil_servant: {
    icon: '🏛️', name: 'Beamte / Behörde',
    level: 'Behörden-E-Mail · Dienstausweis',
    privs: ['Verifizierte Behördenkommunikation', 'Schutz vor Phishing in Behördennamen', 'Authentische Bescheide']
  },
  politician: {
    icon: '🗳️', name: 'Politiker',
    level: 'Offizielle E-Mail · Bundestag-ID',
    privs: ['Schutz vor Deepfakes in eigenem Namen', 'Höchste Vertrauensstufe', 'Verifizierte politische Kommunikation']
  },
  business: {
    icon: '🏢', name: 'Unternehmen',
    level: 'Domain · Handelsregister',
    privs: ['Verifizierte Unternehmenskommunikation', 'HHTTPS-Zertifikat für Websites', 'Schutz vor KI-Phishing']
  },
  craftsman: {
    icon: '🔧', name: 'Handwerker / Meister',
    level: 'Handwerksrolle · Meisterbrief',
    privs: ['Verifizierte Identität in Vergleichsportalen', 'Schutz vor Fake-Bewertungen', 'Authentische Angebote']
  }
};

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return renderNone();

  try {
    const url = new URL(tab.url);
    document.getElementById('headerUrl').textContent = url.hostname;
  } catch {}

  // Get state from background
  chrome.runtime.sendMessage({ type: 'GET_STATE' }, () => {});

  chrome.tabs.sendMessage(tab.id, { type: 'GET_STATE' }, (state) => {
    if (chrome.runtime.lastError || !state) {
      // Try background as fallback
      chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', tabId: tab.id }, (s2) => {
        if (s2 && s2.status) render(s2);
        else renderNone();
      });
      return;
    }
    render(state);
  });

  // Wire up revoke button
  document.getElementById('revokeBtn')?.addEventListener('click', async () => {
    const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
    chrome.tabs.sendMessage(t.id, { type: 'GET_STATE' }, async (state) => {
      if (!state?.token || !state?.issuer) return;
      if (!confirm('Token wirklich widerrufen? Du musst dich danach neu verifizieren.')) return;

      chrome.runtime.sendMessage(
        { type: 'REVOKE_TOKEN', token: state.token, issuer: state.issuer },
        (r) => {
          if (r?.ok) {
            document.getElementById('revokeBtn').textContent = '✓ Widerrufen';
            setTimeout(() => window.close(), 1200);
          } else {
            alert('Widerruf fehlgeschlagen: ' + (r?.error || 'unknown'));
          }
        }
      );
    });
  });
}

function render(state) {
  const statusArea  = document.getElementById('statusArea');
  const statusIcon  = document.getElementById('statusIcon');
  const statusLabel = document.getElementById('statusLabel');
  const statusSub   = document.getElementById('statusSub');

  const isVerified  = state.status === 'verified' && (state.human === true || state.human === 'true');
  const isSupported = state.status === 'unverified' || state.status === 'verified';
  const trustScore  = parseInt(state.trustScore || '0');

  // Status area
  if (isVerified) {
    statusArea.className   = 'status-area verified';
    statusIcon.textContent = '👤';
    statusLabel.textContent = '✓ Menschlich verifiziert';
    statusLabel.className   = 'status-label green';
    statusSub.textContent   = 'HHTTPS aktiv · ' + (state.version || 'v0.4.1');
  } else if (state.status === 'verified' && !isVerified) {
    // Machine token
    statusArea.className   = 'status-area machine';
    statusIcon.textContent = '🤖';
    statusLabel.textContent = 'Maschine verifiziert';
    statusLabel.className   = 'status-label amber';
    statusSub.textContent   = 'Bot oder Maschinenklient (kein Mensch)';
  } else if (state.status === 'unverified' && isSupported) {
    statusArea.className   = 'status-area unverified';
    statusIcon.textContent = '🔓';
    statusLabel.textContent = 'HHTTPS verfügbar';
    statusLabel.className   = 'status-label amber';
    statusSub.textContent   = 'Nicht als Mensch verifiziert';
  } else {
    statusArea.className   = 'status-area';
    statusIcon.textContent = '🔒';
    statusLabel.textContent = 'Kein HHTTPS';
    statusLabel.className   = 'status-label muted';
    statusSub.textContent   = 'Website unterstützt HHTTPS nicht';
    document.getElementById('noHHTTPS').style.display = 'block';
    return;
  }

  // Trust score
  if (isSupported) {
    document.getElementById('trustSection').classList.add('show');
    document.getElementById('trustValue').textContent = trustScore + '/100';
    const fill = document.getElementById('trustFill');
    requestAnimationFrame(() => { fill.style.width = trustScore + '%'; });
    if (trustScore >= 90)      fill.classList.add('high');
    else if (trustScore >= 70) fill.classList.add('mid');
  }

  // Role card
  if (state.role && ROLE_DATA[state.role]) {
    const rd = ROLE_DATA[state.role];
    document.getElementById('roleCard').classList.add('show');
    document.getElementById('roleIcon').textContent  = state.roleIcon || rd.icon;
    document.getElementById('roleName').textContent  = state.roleLabel || rd.name;
    document.getElementById('roleLevel').textContent = rd.level;
    document.getElementById('rolePrivileges').innerHTML =
      rd.privs.map(p => `<div class="priv">${p}</div>`).join('');
  }

  // Details
  if (isSupported) {
    document.getElementById('details').classList.add('show');
    document.getElementById('dStatus').textContent = state.status || '—';
    document.getElementById('dHuman').textContent  = isVerified ? '✓ Ja' : '✗ Nein';
    document.getElementById('dHuman').className    = 'dv ' + (isVerified ? 'g' : 'a');
    document.getElementById('dMethod').textContent = state.method || '—';
    document.getElementById('dIssuer').textContent = state.issuer || '—';

    if (state.token) {
      document.getElementById('dTokenRow').style.display = 'flex';
      document.getElementById('dToken').textContent = state.token.slice(0, 24) + '…';
      document.getElementById('revokeBtn')?.classList.add('show');
    }
  }
}

function renderNone() {
  document.getElementById('statusIcon').textContent  = '🔒';
  document.getElementById('statusLabel').textContent = 'Kein HHTTPS';
  document.getElementById('statusLabel').className   = 'status-label muted';
  document.getElementById('statusSub').textContent   = 'Seite nicht verfügbar oder kein HTTPS';
  document.getElementById('noHHTTPS').style.display  = 'block';
}

document.addEventListener('DOMContentLoaded', init);
