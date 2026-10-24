/**
 * FiribStop Security Engine 2.5.0
 * Full offline-capable scanner for browser/PWA environment.
 * Honest about limitations: this is NOT a replacement for desktop AV.
 */
(function (global) {
  'use strict';

  const DB_KEY = 'fs_av_threat_db_v2';
  const HIST_KEY = 'fs_av_scan_history';
  const QUAR_KEY = 'fs_av_quarantine';
  const SETTINGS_KEY = 'fs_av_settings';
  const MAX_HISTORY = 80;
  const MAX_QUARANTINE = 40;
  const MAX_FILE_SCAN_BYTES = 25 * 1024 * 1024; // 25 MB soft limit for content heuristics

  const DEFAULT_DB = {
    schemaVersion: 2,
    name: 'FiribStop Built-in',
    updatedAt: '2026-10-24',
    hashes: {},
    domains: {},
    suspiciousTlds: ['zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'icu', 'cyou', 'click', 'loan', 'work'],
    dangerousExtensions: {
      '.apk': { risk: 'high', note: 'Android-пакет. Устанавливайте только из Google Play или официального сайта.' },
      '.exe': { risk: 'high', note: 'Исполняемый файл Windows.' },
      '.msi': { risk: 'high', note: 'Установщик Windows.' },
      '.bat': { risk: 'high', note: 'Пакетный скрипт.' },
      '.cmd': { risk: 'high', note: 'Командный скрипт.' },
      '.js': { risk: 'medium', note: 'JavaScript — может быть вредоносным вне браузера.' },
      '.vbs': { risk: 'high', note: 'VBScript.' },
      '.ps1': { risk: 'high', note: 'PowerShell-скрипт.' },
      '.scr': { risk: 'high', note: 'Screensaver — частая маскировка malware.' },
      '.jar': { risk: 'medium', note: 'Java-архив.' },
      '.docm': { risk: 'medium', note: 'Word с макросами.' },
      '.xlsm': { risk: 'medium', note: 'Excel с макросами.' },
      '.hta': { risk: 'high', note: 'HTML Application.' },
      '.lnk': { risk: 'medium', note: 'Ярлык Windows.' }
    },
    contentPatterns: [
      { id: 'eicar', re: /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE/, severity: 'test', label: 'EICAR test signature' },
      { id: 'base64_pe', re: /TVqQAAMAAAAEAAAA/, severity: 'suspicious', label: 'Возможный base64-encoded PE (MZ)' },
      { id: 'ps_enc', re: /powershell.*(-enc|-e\s+|FromBase64String)/i, severity: 'suspicious', label: 'PowerShell с закодированной командой' },
      { id: 'eval_js', re: /eval\s*\(|document\.write\s*\(\s*unescape/i, severity: 'suspicious', label: 'Подозрительный JS eval/unescape' },
      { id: 'miner', re: /coinhive|cryptonight|xmrig|minergate/i, severity: 'miner', label: 'Признаки криптомайнера' }
    ],
    tips: [
      'Не устанавливайте APK из мессенджеров и неизвестных сайтов.',
      'Не переходите по сокращённым ссылкам из SMS.',
      'Банки не просят коды из SMS по телефону.',
      'Обновляйте приложения только из официальных магазинов.',
      'Включите 2FA на важных аккаунтах.'
    ]
  };

  // Seed known test / educational hashes
  DEFAULT_DB.hashes['275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'] = {
    label: 'EICAR test file',
    severity: 'test',
    source: 'eicar.org'
  };

  let runtimeDB = null;
  let lastScanResult = null;

  function ld(key, fallback) {
    try {
      const v = localStorage.getItem(key);
      return v == null ? fallback : JSON.parse(v);
    } catch {
      return fallback;
    }
  }
  function sv(key, val) {
    try {
      localStorage.setItem(key, JSON.stringify(val));
    } catch (e) {
      console.warn('AV storage', e);
    }
  }

  function getSettings() {
    return Object.assign(
      { realtimeHints: true, autoAddToHistory: true, notifyOnThreat: true },
      ld(SETTINGS_KEY, {})
    );
  }

  function loadDB() {
    if (runtimeDB) return runtimeDB;
    const stored = ld(DB_KEY, null);
    runtimeDB = mergeDB(DEFAULT_DB, stored);
    return runtimeDB;
  }

  function mergeDB(base, extra) {
    const out = JSON.parse(JSON.stringify(base));
    if (!extra || typeof extra !== 'object') return out;
    if (Array.isArray(extra.hashes)) {
      for (const h of extra.hashes) {
        if (h && h.sha256) out.hashes[String(h.sha256).toLowerCase()] = {
          label: h.label || 'Imported threat',
          severity: h.severity || 'malicious',
          source: h.source || extra.source || 'import'
        };
      }
    } else if (extra.hashes && typeof extra.hashes === 'object') {
      Object.assign(out.hashes, extra.hashes);
    }
    if (Array.isArray(extra.domains)) {
      for (const d of extra.domains) {
        if (d && d.domain) out.domains[d.domain.toLowerCase()] = d;
      }
    } else if (extra.domains) Object.assign(out.domains, extra.domains);
    if (Array.isArray(extra.suspiciousTlds)) {
      out.suspiciousTlds = [...new Set([...out.suspiciousTlds, ...extra.suspiciousTlds])];
    }
    if (extra.updatedAt) out.updatedAt = extra.updatedAt;
    if (extra.name) out.name = extra.name;
    out.importedAt = extra.importedAt || out.importedAt;
    return out;
  }

  async function importThreatJSON(json) {
    let data = typeof json === 'string' ? JSON.parse(json) : json;
    if (!data || typeof data !== 'object') throw new Error('Некорректный JSON базы');
    const merged = mergeDB(loadDB(), data);
    merged.importedAt = new Date().toISOString();
    runtimeDB = merged;
    // Persist only the importable parts to keep storage small
    const toStore = {
      schemaVersion: 2,
      name: data.name || 'Imported',
      source: data.source || 'user',
      updatedAt: data.updatedAt || new Date().toISOString().slice(0, 10),
      importedAt: merged.importedAt,
      hashes: data.hashes || [],
      domains: data.domains || [],
      suspiciousTlds: data.suspiciousTlds || []
    };
    sv(DB_KEY, toStore);
    return {
      ok: true,
      entries: Array.isArray(data.hashes) ? data.hashes.length : Object.keys(data.hashes || {}).length,
      source: toStore.source,
      importedAt: merged.importedAt
    };
  }

  async function tryLoadBundledDB() {
    try {
      const r = await fetch('./data/threats.json', { cache: 'no-cache' });
      if (!r.ok) return false;
      const data = await r.json();
      await importThreatJSON(data);
      return true;
    } catch {
      return false;
    }
  }

  function dbStats() {
    const db = loadDB();
    return {
      hashCount: Object.keys(db.hashes).length,
      domainCount: Object.keys(db.domains).length,
      tldCount: (db.suspiciousTlds || []).length,
      patternCount: (db.contentPatterns || []).length,
      updatedAt: db.updatedAt,
      importedAt: db.importedAt || null,
      name: db.name
    };
  }

  async function sha256Buffer(buffer) {
    const hash = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function sha256File(file) {
    const buf = await file.arrayBuffer();
    return sha256Buffer(buf);
  }

  function extOf(name) {
    const i = String(name || '').lastIndexOf('.');
    return i >= 0 ? String(name).slice(i).toLowerCase() : '';
  }

  function riskLevelFromFindings(findings) {
    if (!findings.length) return 'clean';
    const order = { clean: 0, test: 1, low: 2, medium: 3, suspicious: 3, high: 4, malicious: 5, miner: 4 };
    let max = 0;
    let level = 'clean';
    for (const f of findings) {
      const s = f.severity || 'medium';
      const v = order[s] ?? 2;
      if (v > max) {
        max = v;
        level = s === 'test' ? 'test' : s === 'malicious' ? 'high' : s === 'miner' ? 'high' : s;
      }
    }
    if (level === 'malicious') level = 'high';
    return level;
  }

  function levelLabel(level) {
    return (
      {
        clean: 'Чисто',
        test: 'Тестовая угроза',
        low: 'Низкий риск',
        medium: 'Средний риск',
        suspicious: 'Подозрительно',
        high: 'Высокий риск',
        malicious: 'Угроза'
      }[level] || level
    );
  }

  function levelColor(level) {
    return (
      {
        clean: 'var(--lo)',
        test: '#7c3aed',
        low: 'var(--me)',
        medium: 'var(--me)',
        suspicious: 'var(--me)',
        high: 'var(--hi)',
        malicious: 'var(--hi)'
      }[level] || 'var(--mu)'
    );
  }

  async function scanFile(file, opts = {}) {
    const db = loadDB();
    const findings = [];
    const name = file.name || 'file';
    const size = file.size || 0;
    const ext = extOf(name);

    // Extension risk
    const extInfo = db.dangerousExtensions[ext];
    if (extInfo) {
      findings.push({
        type: 'extension',
        severity: extInfo.risk || 'medium',
        title: `Опасное расширение ${ext}`,
        detail: extInfo.note
      });
    }

    // Hash
    let hash = '';
    try {
      hash = await sha256File(file);
      const known = db.hashes[hash];
      if (known) {
        findings.push({
          type: 'hash',
          severity: known.severity || 'malicious',
          title: known.label || 'Известная угроза (хеш)',
          detail: `SHA-256 совпал с записью базы. Источник: ${known.source || 'локальная база'}.`
        });
      }
    } catch (e) {
      findings.push({
        type: 'error',
        severity: 'medium',
        title: 'Не удалось вычислить хеш',
        detail: String(e.message || e)
      });
    }

    // Content heuristics (text-like or small files)
    if (size > 0 && size <= MAX_FILE_SCAN_BYTES) {
      try {
        const text = await file.slice(0, Math.min(size, 512 * 1024)).text();
        for (const p of db.contentPatterns || []) {
          if (p.re && p.re.test(text)) {
            findings.push({
              type: 'content',
              severity: p.severity || 'suspicious',
              title: p.label || p.id,
              detail: 'Обнаружен подозрительный шаблон в содержимом файла.'
            });
          }
        }
        // APK is zip — light structural check
        if (ext === '.apk' || ext === '.zip') {
          const head = new Uint8Array(await file.slice(0, 4).arrayBuffer());
          const isZip = head[0] === 0x50 && head[1] === 0x4b;
          if (!isZip && ext === '.apk') {
            findings.push({
              type: 'structure',
              severity: 'high',
              title: 'APK не похож на ZIP-архив',
              detail: 'Настоящий APK — это ZIP. Файл может быть поддельным или повреждённым.'
            });
          }
        }
      } catch {
        // binary — skip text patterns
      }
    } else if (size > MAX_FILE_SCAN_BYTES) {
      findings.push({
        type: 'limit',
        severity: 'low',
        title: 'Файл слишком большой для глубокой эвристики',
        detail: `Проверены расширение и SHA-256. Полный разбор содержимого ограничен ${Math.round(MAX_FILE_SCAN_BYTES / 1024 / 1024)} МБ.`
      });
    }

    const level = riskLevelFromFindings(findings);
    const result = {
      id: Date.now(),
      kind: 'file',
      name,
      size,
      sizeLabel: size > 1048576 ? (size / 1048576).toFixed(2) + ' МБ' : (size / 1024).toFixed(1) + ' КБ',
      ext,
      sha256: hash,
      level,
      levelLabel: levelLabel(level),
      findings,
      scannedAt: new Date().toISOString(),
      scope: 'Браузерный сканер FiribStop: SHA-256, расширение, эвристика содержимого. Не заменяет настольный антивирус и не анализирует исполняемый код глубоко.'
    };

    lastScanResult = result;
    if (getSettings().autoAddToHistory) pushHistory(result);
    return result;
  }

  function scanUrl(rawUrl) {
    const db = loadDB();
    const findings = [];
    let url;
    try {
      const s = String(rawUrl || '').trim();
      url = new URL(s.includes('://') ? s : 'https://' + s);
    } catch {
      return {
        id: Date.now(),
        kind: 'url',
        name: String(rawUrl || ''),
        level: 'medium',
        levelLabel: levelLabel('medium'),
        findings: [{ type: 'parse', severity: 'medium', title: 'Некорректный URL', detail: 'Не удалось разобрать адрес.' }],
        scannedAt: new Date().toISOString(),
        scope: 'Проверка URL по локальным правилам.'
      };
    }

    const host = url.hostname.toLowerCase();
    const parts = host.split('.');
    const tld = parts[parts.length - 1];

    if (db.domains[host]) {
      const d = db.domains[host];
      findings.push({
        type: 'domain',
        severity: d.severity === 'shortener' ? 'medium' : d.severity || 'high',
        title: d.severity === 'shortener' ? 'Сокращатель ссылок' : 'Домен из базы риска',
        detail: d.note || 'Домен отмечен в локальной базе.'
      });
    }

    if ((db.suspiciousTlds || []).includes(tld)) {
      findings.push({
        type: 'tld',
        severity: 'medium',
        title: `Подозрительная зона .${tld}`,
        detail: 'Эта TLD часто используется в фишинговых кампаниях.'
      });
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      findings.push({
        type: 'ip',
        severity: 'high',
        title: 'IP-адрес вместо домена',
        detail: 'Легитимные сервисы редко ведут на «голый» IP.'
      });
    }

    if (host.includes('xn--')) {
      findings.push({
        type: 'punycode',
        severity: 'high',
        title: 'Punycode (возможный IDN-спуфинг)',
        detail: 'Домен использует кодировку xn-- — проверьте визуально, нет ли подмены символов.'
      });
    }

    if ((host.match(/-/g) || []).length >= 3) {
      findings.push({
        type: 'hyphens',
        severity: 'low',
        title: 'Много дефисов в домене',
        detail: 'Частый признак фишинговых доменов-имитаций.'
      });
    }

    if (url.protocol === 'http:') {
      findings.push({
        type: 'http',
        severity: 'low',
        title: 'Незащищённый HTTP',
        detail: 'Нет шифрования TLS. Не вводите пароли и данные карт.'
      });
    }

    // Use global analyzer if available for deeper URL checks
    if (typeof global.analyze === 'function') {
      try {
        const a = global.analyze(url.href);
        if (a && a.score >= 40) {
          findings.push({
            type: 'heuristic',
            severity: a.score >= 70 ? 'high' : 'medium',
            title: 'Эвристика FiribStop: повышенный риск',
            detail: `Оценка анализатора сообщений/ссылок: ${a.score}. Уровень: ${a.level}.`
          });
        }
      } catch (_) {}
    }

    const level = riskLevelFromFindings(findings);
    const result = {
      id: Date.now(),
      kind: 'url',
      name: url.href,
      host,
      level,
      levelLabel: levelLabel(level),
      findings,
      scannedAt: new Date().toISOString(),
      scope: 'Локальные правила + база доменов. Нет облачного репутационного сервиса в реальном времени.'
    };
    lastScanResult = result;
    if (getSettings().autoAddToHistory) pushHistory(result);
    return result;
  }

  function pushHistory(result) {
    const hist = ld(HIST_KEY, []);
    hist.unshift({
      id: result.id,
      kind: result.kind,
      name: result.name,
      level: result.level,
      sha256: result.sha256 || null,
      findingsCount: (result.findings || []).length,
      scannedAt: result.scannedAt
    });
    sv(HIST_KEY, hist.slice(0, MAX_HISTORY));
  }

  function getHistory() {
    return ld(HIST_KEY, []);
  }

  function clearHistory() {
    sv(HIST_KEY, []);
  }

  function addToQuarantine(result) {
    if (!result) return false;
    const q = ld(QUAR_KEY, []);
    q.unshift({
      id: result.id || Date.now(),
      name: result.name,
      sha256: result.sha256 || null,
      level: result.level,
      findings: result.findings || [],
      quarantinedAt: new Date().toISOString(),
      note: 'Локальная запись. Файл на диске не перемещался — браузер не имеет такого доступа.'
    });
    sv(QUAR_KEY, q.slice(0, MAX_QUARANTINE));
    return true;
  }

  function getQuarantine() {
    return ld(QUAR_KEY, []);
  }

  function removeFromQuarantine(id) {
    const q = ld(QUAR_KEY, []).filter((x) => x.id !== id);
    sv(QUAR_KEY, q);
  }

  function clearQuarantine() {
    sv(QUAR_KEY, []);
  }

  function protectionStatus() {
    const stats = dbStats();
    const hist = getHistory();
    const recentThreats = hist.filter((h) => h.level === 'high' || h.level === 'malicious').length;
    return {
      active: true,
      mode: 'offline-first',
      database: stats,
      recentScans: hist.length,
      recentThreats,
      lastScan: hist[0] || null,
      tips: loadDB().tips || DEFAULT_DB.tips
    };
  }

  // ---------- UI helpers (used by V.antivirus) ----------

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function renderFindings(findings) {
    if (!findings || !findings.length) {
      return '<p class="good">Подозрительных признаков не найдено.</p>';
    }
    return findings
      .map(
        (f) =>
          `<div class="f"><b>${esc(f.title)}</b><span class="mu">${esc(f.severity || '')}</span><p>${esc(f.detail || '')}</p></div>`
      )
      .join('');
  }

  function renderScanResult(result) {
    if (!result) return '<p class="mu">Результат появится после проверки.</p>';
    const color = levelColor(result.level);
    return `
      <div class="card" style="border-color:${color}">
        <div class="card-head">
          <h2 style="margin:0">Результат: ${esc(result.levelLabel)}</h2>
          <span class="pill" style="background:${color}">${esc(result.level)}</span>
        </div>
        <p><b>${esc(result.name)}</b></p>
        ${result.sizeLabel ? `<p class="mu">Размер: ${esc(result.sizeLabel)}</p>` : ''}
        ${result.sha256 ? `<p class="mu" style="word-break:break-all">SHA-256: <code>${esc(result.sha256)}</code></p>` : ''}
        ${renderFindings(result.findings)}
        <p class="mu" style="margin-top:12px">${esc(result.scope)}</p>
        <div class="row" style="margin-top:12px">
          <button type="button" class="btn" onclick="FiribStopAV.uiQuarantineLast()">🔒 В карантин (запись)</button>
          <button type="button" class="btn" onclick="FiribStopAV.uiCopyReport()">📋 Копировать отчёт</button>
        </div>
      </div>`;
  }

  function renderHistoryList() {
    const hist = getHistory();
    if (!hist.length) return '<p class="mu">Журнал пуст.</p>';
    return hist
      .slice(0, 20)
      .map(
        (h) =>
          `<div class="region-row" style="display:flex;justify-content:space-between;gap:8px;padding:8px 0;border-bottom:1px solid var(--bd)">
            <span><b>${esc(h.kind)}</b> · ${esc((h.name || '').slice(0, 48))}${h.name && h.name.length > 48 ? '…' : ''}</span>
            <span style="color:${levelColor(h.level)};font-weight:700">${esc(levelLabel(h.level))}</span>
          </div>`
      )
      .join('');
  }

  function renderQuarantineList() {
    const q = getQuarantine();
    if (!q.length) return '<p class="mu">Карантин пуст. Это локальный список меток — файлы на диске не перемещаются.</p>';
    return q
      .map(
        (item) =>
          `<div class="card" style="padding:12px">
            <b>${esc(item.name)}</b>
            <p class="mu">${esc(item.quarantinedAt)} · ${esc(levelLabel(item.level))}</p>
            ${item.sha256 ? `<p class="mu" style="word-break:break-all"><code>${esc(item.sha256)}</code></p>` : ''}
            <button type="button" class="btn" onclick="FiribStopAV.uiRemoveQuarantine(${item.id})">Удалить запись</button>
          </div>`
      )
      .join('');
  }

  function renderDashboard() {
    const st = protectionStatus();
    const db = st.database;
    const tip = (st.tips && st.tips[Math.floor(Math.random() * st.tips.length)]) || '';
    return `
      <div class="card" style="background:linear-gradient(135deg,#0b2545,#0f766e);color:#fff;border:0;padding:24px">
        <div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">
          <div style="font-size:52px" aria-hidden="true">🛡️</div>
          <div style="flex:1;min-width:200px">
            <div class="eyebrow" style="color:#5de4d2">FIRIBSTOP SECURITY</div>
            <h1 style="color:#fff;margin:6px 0 8px;font-size:28px">Антивирусный центр</h1>
            <p style="margin:0;color:#cfeee9">Защита активна в режиме offline-first. Проверка файлов, ссылок и локальной базы угроз.</p>
          </div>
          <div style="text-align:center;padding:12px 16px;border-radius:16px;background:#ffffff18;border:1px solid #ffffff33">
            <div style="font-size:13px;color:#a7f3d0">СТАТУС</div>
            <b style="font-size:20px">Активна</b>
          </div>
        </div>
        <div class="grid" style="margin-top:20px">
          <div style="padding:14px;border-radius:14px;background:#ffffff14">
            <div style="font-size:12px;opacity:.85">БАЗА ХЕШЕЙ</div>
            <b style="font-size:26px">${db.hashCount}</b>
          </div>
          <div style="padding:14px;border-radius:14px;background:#ffffff14">
            <div style="font-size:12px;opacity:.85">ДОМЕНЫ / TLD</div>
            <b style="font-size:26px">${db.domainCount + db.tldCount}</b>
          </div>
          <div style="padding:14px;border-radius:14px;background:#ffffff14">
            <div style="font-size:12px;opacity:.85">ПРОВЕРОК</div>
            <b style="font-size:26px">${st.recentScans}</b>
          </div>
        </div>
      </div>

      <div class="map-disclaimer">
        <b>⚠ Честные ограничения</b>
        Это браузерный/PWA-сканер. Он не имеет доступа к ядру ОС, не блокирует процессы в реальном времени и не заменяет Kaspersky, Windows Defender или антивирус на телефоне. Используйте как дополнительный слой цифровой гигиены.
      </div>

      <div class="pro-grid" style="margin-top:16px">
        <div class="card">
          <h2>⚡ Быстрая проверка</h2>
          <p class="mu">Файл (APK, документы, архивы) или ссылка. Всё считается локально на вашем устройстве.</p>
          <input id="avFilePicker" type="file" hidden onchange="FiribStopAV.uiScanFile(this)">
          <button type="button" class="btn p" onclick="document.getElementById('avFilePicker').click()">📂 Проверить файл</button>
          <div class="row">
            <input id="avUrlInput" type="url" placeholder="https://example.com/..." style="flex:1;padding:12px;border:1px solid var(--bd);border-radius:12px;background:var(--sf);color:var(--tx);font:inherit">
          </div>
          <button type="button" class="btn" onclick="FiribStopAV.uiScanUrl()">🔗 Проверить ссылку</button>
          <button type="button" class="btn" onclick="FiribStopAV.uiScanTextAsUrl()">📝 Проверить текст/сообщение (через анализатор)</button>
          <div id="avScanResult">${lastScanResult ? renderScanResult(lastScanResult) : '<p class="mu">Загрузите файл или вставьте ссылку.</p>'}</div>
        </div>
        <div class="card">
          <h2>📊 Состояние</h2>
          <p class="mu">База: <b>${esc(db.name || 'Built-in')}</b></p>
          <p class="mu">Обновлена: ${esc(db.updatedAt || '—')}${db.importedAt ? '<br>Импорт: ' + esc(new Date(db.importedAt).toLocaleString('ru-RU')) : ''}</p>
          <p class="mu">Угроз в журнале: <b>${st.recentThreats}</b></p>
          <div class="tip-row"><span>💡</span><div><b>Совет дня</b><p>${esc(tip)}</p></div></div>
          <button type="button" class="btn" onclick="FiribStopAV.uiLoadBundled()">🔄 Загрузить встроенную базу</button>
          <button type="button" class="btn" onclick="document.getElementById('avDbPicker').click()">📥 Импорт JSON базы</button>
          <input id="avDbPicker" type="file" accept="application/json,.json" hidden onchange="FiribStopAV.uiImportDb(this)">
          <p id="avDbStatus" class="status-note">Хешей: ${db.hashCount}. Доменов: ${db.domainCount}.</p>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h2>🧾 Журнал проверок</h2>
          <button type="button" class="btn" style="width:auto;min-height:40px;padding:8px 14px" onclick="FiribStopAV.uiClearHistory()">Очистить</button>
        </div>
        <div id="avHistory">${renderHistoryList()}</div>
      </div>

      <div class="card">
        <div class="card-head"><h2>🔒 Карантин (локальные метки)</h2>
          <button type="button" class="btn" style="width:auto;min-height:40px;padding:8px 14px" onclick="FiribStopAV.uiClearQuarantine()">Очистить</button>
        </div>
        <p class="mu">Браузер не может перемещать файлы в системный карантин. Здесь хранятся только записи о подозрительных объектах.</p>
        <div id="avQuarantine">${renderQuarantineList()}</div>
      </div>
    `;
  }

  // UI action bridges
  const ui = {
    async uiScanFile(input) {
      const file = input?.files?.[0];
      if (!file) return;
      const box = document.getElementById('avScanResult');
      if (box) box.innerHTML = '<div class="av-scanning">Сканирование файла…</div>';
      try {
        const result = await scanFile(file);
        if (box) box.innerHTML = renderScanResult(result);
        const hist = document.getElementById('avHistory');
        if (hist) hist.innerHTML = renderHistoryList();
        if (typeof global.toast === 'function') {
          global.toast(result.level === 'clean' ? 'Файл: чисто' : 'Найдены признаки риска');
        }
      } catch (e) {
        if (box) box.innerHTML = `<p class="err">${esc(e.message || e)}</p>`;
      }
      input.value = '';
    },
    uiScanUrl() {
      const input = document.getElementById('avUrlInput');
      const raw = input?.value?.trim();
      if (!raw) {
        if (typeof global.toast === 'function') global.toast('Вставьте ссылку');
        return;
      }
      const result = scanUrl(raw);
      const box = document.getElementById('avScanResult');
      if (box) box.innerHTML = renderScanResult(result);
      const hist = document.getElementById('avHistory');
      if (hist) hist.innerHTML = renderHistoryList();
    },
    uiScanTextAsUrl() {
      if (typeof global.go === 'function') global.go('check');
      else if (typeof global.toast === 'function') global.toast('Откройте раздел проверки сообщений');
    },
    uiQuarantineLast() {
      if (!lastScanResult) return;
      addToQuarantine(lastScanResult);
      const q = document.getElementById('avQuarantine');
      if (q) q.innerHTML = renderQuarantineList();
      if (typeof global.toast === 'function') global.toast('Добавлено в карантин (запись)');
    },
    uiCopyReport() {
      if (!lastScanResult) return;
      const r = lastScanResult;
      const text = [
        'FiribStop AV Report',
        '==================',
        `Object: ${r.name}`,
        `Level: ${r.levelLabel} (${r.level})`,
        r.sha256 ? `SHA-256: ${r.sha256}` : '',
        r.sizeLabel ? `Size: ${r.sizeLabel}` : '',
        `Scanned: ${r.scannedAt}`,
        '',
        'Findings:',
        ...(r.findings || []).map((f) => `- [${f.severity}] ${f.title}: ${f.detail || ''}`),
        '',
        r.scope
      ]
        .filter(Boolean)
        .join('\n');
      navigator.clipboard?.writeText(text).then(
        () => typeof global.toast === 'function' && global.toast('Отчёт скопирован'),
        () => typeof global.toast === 'function' && global.toast('Не удалось скопировать')
      );
    },
    async uiImportDb(input) {
      const file = input?.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const res = await importThreatJSON(text);
        const st = document.getElementById('avDbStatus');
        if (st) st.textContent = `Импортировано записей: ${res.entries}. Источник: ${res.source}.`;
        if (typeof global.toast === 'function') global.toast('База импортирована');
        if (typeof global.render === 'function') global.render(true);
      } catch (e) {
        if (typeof global.toast === 'function') global.toast('Ошибка импорта: ' + (e.message || e));
      }
      input.value = '';
    },
    async uiLoadBundled() {
      const ok = await tryLoadBundledDB();
      const st = document.getElementById('avDbStatus');
      const stats = dbStats();
      if (st) st.textContent = ok
        ? `Встроенная база загружена. Хешей: ${stats.hashCount}.`
        : `Используется встроенный минимум. Хешей: ${stats.hashCount}.`;
      if (typeof global.toast === 'function') global.toast(ok ? 'База обновлена' : 'Локальный минимум активен');
    },
    uiClearHistory() {
      if (confirm('Очистить журнал проверок?')) {
        clearHistory();
        const hist = document.getElementById('avHistory');
        if (hist) hist.innerHTML = renderHistoryList();
      }
    },
    uiClearQuarantine() {
      if (confirm('Очистить карантин?')) {
        clearQuarantine();
        const q = document.getElementById('avQuarantine');
        if (q) q.innerHTML = renderQuarantineList();
      }
    },
    uiRemoveQuarantine(id) {
      removeFromQuarantine(id);
      const q = document.getElementById('avQuarantine');
      if (q) q.innerHTML = renderQuarantineList();
    }
  };

  // Public API
  global.FiribStopAV = {
    scanFile,
    scanUrl,
    importThreatJSON,
    tryLoadBundledDB,
    dbStats,
    protectionStatus,
    getHistory,
    clearHistory,
    addToQuarantine,
    getQuarantine,
    removeFromQuarantine,
    clearQuarantine,
    renderDashboard,
    renderScanResult,
    get lastScanResult() {
      return lastScanResult;
    },
    ...ui
  };

  // Preload DB
  loadDB();
  tryLoadBundledDB().catch(() => {});
})(typeof window !== 'undefined' ? window : globalThis);
