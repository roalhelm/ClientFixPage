/* Client Fix Page: matches a Get-ClientHealth.ps1 report against data/catalog.json.
   Everything runs in the browser. Report data is never sent anywhere.
   All report content is written with textContent, never innerHTML. */
(function () {
  'use strict';

  var SUPPORTED_SCHEMA_MAJOR = '1';
  var STATUS_ORDER = { fail: 0, warn: 1, unknown: 2, info: 3, pass: 4 };
  var SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };
  var STATUS_LABEL = { fail: 'Problem', warn: 'Warning', unknown: 'Not checked', info: 'Info', pass: 'OK' };
  var FIX_STATUS_LABEL = {
    'available': 'Script available',
    'needs-fix': 'Script needs review',
    'planned': 'No script yet',
    'manual': 'Step-by-step guide'
  };

  var catalog = null;
  var catalogById = {};
  var report = null;
  var areaFilter = 'all';

  function $(id) { return document.getElementById(id); }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  function showError(message) {
    var box = $('error');
    box.textContent = message;
    box.hidden = !message;
  }

  function safeUrl(url) {
    // Only https links from the catalog are rendered as links.
    return typeof url === 'string' && /^https:\/\//i.test(url) ? url : null;
  }

  function copyText(text, button) {
    var done = function () {
      var old = button.textContent;
      button.textContent = 'Copied';
      setTimeout(function () { button.textContent = old; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else {
      fallbackCopy(text); done();
    }
  }

  function fallbackCopy(text) {
    var area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); } catch (e) { /* ignore */ }
    document.body.removeChild(area);
  }

  function commandBlock(text) {
    var wrap = el('div', 'cmd');
    var pre = el('pre');
    pre.appendChild(el('code', null, text));
    var button = el('button', 'btn small', 'Copy');
    button.type = 'button';
    button.addEventListener('click', function () { copyText(text, button); });
    wrap.appendChild(pre);
    wrap.appendChild(button);
    return wrap;
  }

  // ---------- Parsing and validation ----------

  function parseReport(text) {
    if (!text || !text.trim()) { throw new Error('The report is empty. Paste the JSON or choose the report file.'); }
    var cleaned = text.replace(/^﻿/, '').trim();
    var data;
    try {
      data = JSON.parse(cleaned);
    } catch (e) {
      throw new Error('This is not valid JSON. Load the file written by Get-ClientHealth.ps1 without changes.');
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('This JSON is not a client health report.');
    }
    if (!Array.isArray(data.checks)) {
      throw new Error('This JSON has no "checks" list, so it is not a Get-ClientHealth.ps1 report.');
    }
    var schema = String(data.schemaVersion || '');
    if (schema.split('.')[0] !== SUPPORTED_SCHEMA_MAJOR) {
      throw new Error('Report schema version "' + (schema || 'missing') + '" is not supported. This page reads version ' + SUPPORTED_SCHEMA_MAJOR + '.x.');
    }
    data.checks = data.checks.filter(function (c) {
      return c && typeof c === 'object' && typeof c.id === 'string';
    }).map(function (c) {
      return {
        id: c.id,
        area: typeof c.area === 'string' ? c.area : 'other',
        status: STATUS_ORDER.hasOwnProperty(c.status) ? c.status : 'unknown',
        title: typeof c.title === 'string' ? c.title : c.id,
        detail: typeof c.detail === 'string' ? c.detail : '',
        evidence: c.evidence === undefined ? null : c.evidence
      };
    });
    return data;
  }

  // ---------- Rendering ----------

  function renderOverview() {
    var box = $('overview');
    clear(box);
    var checks = report.checks;
    var count = function (status) { return checks.filter(function (c) { return c.status === status; }).length; };
    var fails = count('fail'), warns = count('warn'), unknowns = count('unknown'), passes = count('pass');
    var overall = fails ? 'unhealthy' : (warns ? 'attention' : 'healthy');
    var label = { unhealthy: 'Not healthy', attention: 'Needs attention', healthy: 'Healthy' }[overall];

    var left = el('div');
    left.appendChild(el('p', 'overall ' + overall, label));
    var device = report.device || {};
    var name = device.computerName || 'Unknown device';
    left.appendChild(el('p', 'meta', name));
    box.appendChild(left);

    var mid = el('div');
    var os = [device.osCaption, device.displayVersion].filter(Boolean).join(' ');
    var build = device.build ? ('Build ' + device.build + (device.ubr !== null && device.ubr !== undefined ? '.' + device.ubr : '')) : '';
    var model = [device.manufacturer, device.model].filter(Boolean).join(' ');
    [os, build, model].filter(Boolean).forEach(function (line) { mid.appendChild(el('p', 'meta', line)); });
    if (report.generatedAt) {
      var when = new Date(report.generatedAt);
      if (!isNaN(when.getTime())) { mid.appendChild(el('p', 'meta', 'Report from ' + when.toLocaleString())); }
    }
    box.appendChild(mid);

    var counts = el('div', 'counts');
    counts.appendChild(el('span', 'badge fail', fails + ' problem' + (fails === 1 ? '' : 's')));
    counts.appendChild(el('span', 'badge warn', warns + ' warning' + (warns === 1 ? '' : 's')));
    counts.appendChild(el('span', 'badge unknown', unknowns + ' not checked'));
    counts.appendChild(el('span', 'badge pass', passes + ' OK'));
    box.appendChild(counts);

    if (report.elevated === false) {
      box.appendChild(el('p', 'notice', 'The script did not run elevated, so some checks could not run. Run it as Administrator for a complete result.'));
    }
    if (report.generatedAt) {
      var ageDays = (Date.now() - new Date(report.generatedAt).getTime()) / 86400000;
      if (ageDays > 2) {
        box.appendChild(el('p', 'notice', 'This report is ' + Math.floor(ageDays) + ' days old. Run the diagnostic again for the current state.'));
      }
    }
  }

  function renderFilters() {
    var box = $('filters');
    clear(box);
    var areas = [];
    report.checks.forEach(function (c) { if (areas.indexOf(c.area) === -1) { areas.push(c.area); } });
    areas = areas.filter(function (a) { return a !== 'system'; }).sort();
    ['all'].concat(areas).forEach(function (area) {
      var open = report.checks.filter(function (c) {
        return (area === 'all' || c.area === area) && (c.status === 'fail' || c.status === 'warn');
      }).length;
      var button = el('button', 'btn small', (area === 'all' ? 'All areas' : area.charAt(0).toUpperCase() + area.slice(1)) + ' (' + open + ')');
      button.type = 'button';
      button.setAttribute('aria-pressed', String(areaFilter === area));
      button.setAttribute('data-area', area);
      button.addEventListener('click', function () { areaFilter = area; renderFilters(); renderLists(); refocus('filters', area); });
      box.appendChild(button);
    });
  }

  function renderFix(fix) {
    var box = el('div', 'fix');
    var meta = el('div', 'fix-meta');
    meta.appendChild(el('h4', null, 'Recommended fix'));
    meta.appendChild(el('span', 'badge ' + (fix.status === 'available' ? 'pass' : (fix.status === 'needs-fix' ? 'warn' : (fix.status === 'manual' ? 'info' : 'neutral'))), FIX_STATUS_LABEL[fix.status] || fix.status));
    if (fix.risk) { meta.appendChild(el('span', 'badge neutral', 'Risk: ' + fix.risk)); }
    box.appendChild(meta);

    if (fix.note) { box.appendChild(el('p', 'note', fix.note)); }

    var repoUrl = safeUrl(fix.repo);
    var downloadUrl = safeUrl(fix.download);
    if (repoUrl || downloadUrl) {
      var links = el('p');
      if (downloadUrl) {
        var dl = el('a', 'btn small', 'Download ' + (fix.script ? fix.script.split('/').pop() : 'script'));
        dl.href = downloadUrl; dl.target = '_blank'; dl.rel = 'noopener noreferrer';
        links.appendChild(dl);
        links.appendChild(document.createTextNode(' '));
      }
      if (repoUrl) {
        var repo = el('a', null, 'Open repository');
        repo.href = repoUrl; repo.target = '_blank'; repo.rel = 'noopener noreferrer';
        links.appendChild(repo);
      }
      box.appendChild(links);
    }
    if (fix.command) {
      box.appendChild(el('p', null, 'Run in an elevated prompt on the client:'));
      box.appendChild(commandBlock(fix.command));
    }
    if (Array.isArray(fix.manualSteps) && fix.manualSteps.length) {
      box.appendChild(el('p', null, 'Manual steps:'));
      var list = el('ol');
      fix.manualSteps.forEach(function (step) { list.appendChild(el('li', null, step)); });
      box.appendChild(list);
    }
    return box;
  }

  function renderCard(check) {
    var fix = catalogById[check.id];
    var card = el('article', 'card ' + check.status);
    var head = el('div', 'card-head');
    head.appendChild(el('h3', null, check.title));
    head.appendChild(el('span', 'badge ' + check.status, STATUS_LABEL[check.status]));
    if (fix && fix.severity) { head.appendChild(el('span', 'badge neutral', 'Severity: ' + fix.severity)); }
    card.appendChild(head);
    card.appendChild(el('p', 'id', check.id + ' · ' + check.area));
    if (check.detail) { card.appendChild(el('p', 'detail', check.detail)); }

    if (fix) {
      card.appendChild(renderFix(fix));
    } else {
      var none = el('div', 'fix');
      none.appendChild(el('p', null, 'The catalog has no fix for this finding yet.'));
      card.appendChild(none);
    }

    if (check.evidence !== null) {
      var details = el('details');
      details.appendChild(el('summary', null, 'Evidence from the report'));
      var pre = el('pre');
      pre.appendChild(el('code', null, JSON.stringify(check.evidence, null, 2)));
      details.appendChild(pre);
      card.appendChild(details);
    }
    return card;
  }

  function renderLine(check) {
    var line = el('div', 'line');
    line.appendChild(el('span', 'badge ' + check.status, STATUS_LABEL[check.status]));
    line.appendChild(el('span', 't', check.title));
    line.appendChild(el('span', 'id', check.id));
    if (check.detail && check.status !== 'pass') { line.appendChild(el('span', 'd', check.detail)); }
    return line;
  }

  function renderLists() {
    var inArea = report.checks.filter(function (c) { return areaFilter === 'all' || c.area === areaFilter; });
    var open = inArea.filter(function (c) { return c.status === 'fail' || c.status === 'warn'; });
    open.sort(function (a, b) {
      if (STATUS_ORDER[a.status] !== STATUS_ORDER[b.status]) { return STATUS_ORDER[a.status] - STATUS_ORDER[b.status]; }
      var sa = catalogById[a.id] ? SEVERITY_ORDER[catalogById[a.id].severity] : 3;
      var sb = catalogById[b.id] ? SEVERITY_ORDER[catalogById[b.id].severity] : 3;
      if (sa === undefined) { sa = 3; }
      if (sb === undefined) { sb = 3; }
      return sa - sb;
    });

    var findings = $('findings');
    clear(findings);
    $('findings-title').textContent = open.length ? 'Recommended fixes (' + open.length + ')' : 'Recommended fixes';
    if (open.length === 0) {
      findings.appendChild(el('p', 'empty', areaFilter === 'all' ? 'No problems found. This client looks healthy.' : 'No problems found in this area.'));
    } else {
      open.forEach(function (check) { findings.appendChild(renderCard(check)); });
    }

    var unknown = inArea.filter(function (c) { return c.status === 'unknown'; });
    $('unknown-box').hidden = unknown.length === 0;
    $('unknown-summary').textContent = 'Checks that could not run (' + unknown.length + ')';
    clear($('unknown'));
    unknown.forEach(function (check) { $('unknown').appendChild(renderLine(check)); });

    var passed = inArea.filter(function (c) { return c.status === 'pass' || c.status === 'info'; });
    $('passed-box').hidden = passed.length === 0;
    $('passed-summary').textContent = 'Checks without problems (' + passed.length + ')';
    clear($('passed'));
    passed.forEach(function (check) { $('passed').appendChild(renderLine(check)); });
  }

  function analyse(text) {
    showError('');
    if (!catalog) { showError('The fix catalog could not be loaded, so findings cannot be matched. Reload the page.'); return; }
    try {
      report = parseReport(text);
    } catch (e) {
      report = null;
      $('result').hidden = true;
      showError(e.message);
      return;
    }
    areaFilter = 'all';
    renderOverview();
    renderFilters();
    renderLists();
    $('result').hidden = false;
    $('clear').hidden = false;
    $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ---------- Problem search (works without a report) ----------

  var AREA_LABEL = { patching: 'Patching', intune: 'Intune', defender: 'Defender', identity: 'Entra ID', network: 'Network' };
  // Words admins type for an area. A word that is not in an entry still matches the entries of its area.
  var AREA_WORDS = {
    patching: ['update', 'updates', 'patch', 'patches', 'patching', 'wsus', 'wufb', 'autopatch', 'cumulative', 'kb', 'wuauserv', 'upgrade', 'feature', 'quality'],
    intune: ['intune', 'mdm', 'sync', 'enrollment', 'enrolment', 'enroll', 'company', 'portal', 'ime', 'win32', 'app', 'apps', 'compliance', 'compliant', 'managed'],
    defender: ['defender', 'antivirus', 'av', 'malware', 'virus', 'signature', 'signatures', 'mde', 'edr', 'tamper', 'realtime', 'protection', 'onboarding', 'onboarded', 'sensor'],
    identity: ['entra', 'aad', 'azuread', 'azure', 'prt', 'sso', 'hello', 'login', 'logon', 'signin', 'token', 'join', 'joined', 'hybrid'],
    network: ['network', 'proxy', 'firewall', 'endpoint', 'endpoints', 'dns', 'unreachable', 'connectivity', 'internet', 'offline', 'blocked']
  };
  // Words that mean the same thing. A word also matches entries that contain a word from its group.
  var SYNONYMS = [
    ['reboot', 'restart', 'pending'],
    ['disk', 'space', 'storage', 'drive', 'full', 'ssd', 'hdd'],
    ['disabled', 'stopped', 'running', 'service', 'services'],
    ['fail', 'fails', 'failed', 'failing', 'error', 'errors', 'broken'],
    ['old', 'outdated', 'stale', 'behind', 'missing']
  ];
  var searchArea = 'all';

  function haystack(fix) {
    return [fix.id, fix.id.replace(/[._]/g, ' '), fix.area, AREA_LABEL[fix.area], fix.title, fix.note, fix.script, fix.command]
      .concat(Array.isArray(fix.manualSteps) ? fix.manualSteps : [])
      .filter(Boolean).join(' ').toLowerCase();
  }

  function hasWord(text, word) {
    // Word start match, so "sync" finds "syncing" but "av" does not find "available".
    var escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp('(^|[^a-z0-9])' + escaped + (word.length < 4 ? '($|[^a-z0-9])' : ''), 'i').test(text);
  }

  function stem(word) {
    var m = /^(.{3,}?)(ing|ed|es|s)$/.exec(word);
    return m ? m[1] : word;
  }

  function wordScore(fix, word, title, hay) {
    var score = directScore(fix, word, title, hay);
    if (score) { return score; }
    var base = stem(word);
    return base !== word ? directScore(fix, base, title, hay) : 0;
  }

  function directScore(fix, word, title, hay) {
    if (hasWord(title, word)) { return 4; }
    if (hasWord(hay, word)) { return 2; }
    if (AREA_WORDS[fix.area] && AREA_WORDS[fix.area].indexOf(word) !== -1) { return 1; }
    for (var i = 0; i < SYNONYMS.length; i++) {
      if (SYNONYMS[i].indexOf(word) === -1) { continue; }
      for (var j = 0; j < SYNONYMS[i].length; j++) {
        if (SYNONYMS[i][j] !== word && hasWord(hay, SYNONYMS[i][j])) { return 1; }
      }
    }
    return 0;
  }

  function scoreFix(fix, words) {
    if (!words.length) { return 1; }
    var hay = fix._hay || (fix._hay = haystack(fix));
    var title = (String(fix.title || '') + ' ' + fix.id.replace(/[._]/g, ' ')).toLowerCase();
    var score = 0;
    var direct = 0;
    for (var i = 0; i < words.length; i++) {
      var w = wordScore(fix, words[i], title, hay);
      if (w >= 2) { direct++; }
      score += w;
    }
    // Every word has to match unless at least one word matched the entry text directly.
    var matched = words.filter(function (word) { return wordScore(fix, word, title, hay) > 0; }).length;
    if (matched === words.length) { return score + 10; }
    return matched >= Math.ceil(words.length / 2) && (direct || words.length > 1) ? score : 0;
  }

  function severityRank(fix) {
    return SEVERITY_ORDER.hasOwnProperty(fix.severity) ? SEVERITY_ORDER[fix.severity] : 3;
  }

  // Re-render a filter group and keep keyboard focus on the button that was activated.
  function refocus(boxId, area) {
    var target = $(boxId).querySelector('[data-area="' + area + '"]');
    if (target) { target.focus(); }
  }

  function renderSearchAreas() {
    var box = $('search-areas');
    clear(box);
    var areas = [];
    catalog.fixes.forEach(function (f) { if (f && f.area && areas.indexOf(f.area) === -1) { areas.push(f.area); } });
    ['all'].concat(areas).forEach(function (area) {
      var n = area === 'all' ? catalog.fixes.length : catalog.fixes.filter(function (f) { return f.area === area; }).length;
      var label = area === 'all' ? 'All' : (AREA_LABEL[area] || area.charAt(0).toUpperCase() + area.slice(1));
      var button = el('button', 'btn small', label + ' (' + n + ')');
      button.type = 'button';
      button.setAttribute('aria-pressed', String(searchArea === area));
      button.setAttribute('data-area', area);
      button.addEventListener('click', function () { searchArea = area; renderSearchAreas(); renderSearch(); refocus('search-areas', area); });
      box.appendChild(button);
    });
  }

  function renderSearchResult(fix, open) {
    var item = el('details', 'hit');
    if (open) { item.open = true; }
    var summary = el('summary');
    var head = el('span', 'hit-head');
    head.appendChild(el('span', 'hit-title', fix.title || fix.id));
    head.appendChild(el('span', 'badge ' + (fix.status === 'available' ? 'pass' : (fix.status === 'needs-fix' ? 'warn' : (fix.status === 'manual' ? 'info' : 'neutral'))), FIX_STATUS_LABEL[fix.status] || fix.status));
    summary.appendChild(head);
    summary.appendChild(el('span', 'id', fix.id + ' · ' + (AREA_LABEL[fix.area] || fix.area) + (fix.severity ? ' · severity ' + fix.severity : '')));
    item.appendChild(summary);
    item.appendChild(renderFix(fix));
    return item;
  }

  function renderSearch() {
    if (!catalog) { return; }
    var STOP = ['the', 'a', 'an', 'is', 'are', 'not', 'no', 'on', 'of', 'to', 'in', 'and', 'or', 'does', 'doesnt', 'dont', 'cant', 'my', 'for', 'with', 'client', 'device', 'pc', 'windows'];
    var query = $('search').value.toLowerCase().replace(/[^a-z0-9.\s]/g, ' ').trim();
    var words = query ? query.split(/\s+/).filter(function (w) { return w.length > 1 && STOP.indexOf(w) === -1; }) : [];
    var hits = catalog.fixes.filter(function (f) {
      return f && typeof f.id === 'string' && (searchArea === 'all' || f.area === searchArea);
    }).map(function (f) { return { fix: f, score: scoreFix(f, words) }; })
      .filter(function (h) { return h.score > 0; });
    if (words.length) {
      hits.sort(function (a, b) {
        if (b.score !== a.score) { return b.score - a.score; }
        return severityRank(a.fix) - severityRank(b.fix);
      });
    }
    var box = $('search-results');
    clear(box);
    $('search-count').textContent = hits.length === 1 ? '1 solution' : hits.length + ' solutions';
    if (!hits.length) {
      box.appendChild(el('p', 'search-empty', 'No matching solution in the catalog. Try another word, pick an area, or run the diagnostic for an exact answer.'));
      return;
    }
    hits.forEach(function (h, i) { box.appendChild(renderSearchResult(h.fix, words.length > 0 && i === 0 && hits.length <= 3)); });
  }

  function initSearch() {
    var input = $('search');
    var timer = null;
    input.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(renderSearch, 120);
    });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { input.value = ''; renderSearch(); }
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-query]'), function (button) {
      button.addEventListener('click', function () {
        input.value = button.getAttribute('data-query');
        searchArea = 'all';
        renderSearchAreas();
        renderSearch();
        input.focus();
      });
    });
  }

  // ---------- Input handling ----------

  function readFile(file) {
    if (!file) { return; }
    if (file.size > 5 * 1024 * 1024) { showError('This file is larger than 5 MB and cannot be a client health report.'); return; }
    var reader = new FileReader();
    reader.onload = function () { $('paste').value = String(reader.result); analyse(String(reader.result)); };
    reader.onerror = function () { showError('The file could not be read.'); };
    reader.readAsText(file);
  }

  function init() {
    var drop = $('drop');
    var input = $('file');
    drop.addEventListener('click', function () { input.click(); });
    drop.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    input.addEventListener('change', function () { readFile(input.files[0]); input.value = ''; });
    ['dragenter', 'dragover'].forEach(function (name) {
      drop.addEventListener(name, function (e) { e.preventDefault(); drop.classList.add('over'); });
    });
    ['dragleave', 'drop'].forEach(function (name) {
      drop.addEventListener(name, function (e) { e.preventDefault(); drop.classList.remove('over'); });
    });
    drop.addEventListener('drop', function (e) { readFile(e.dataTransfer.files[0]); });

    initSearch();

    $('analyse').addEventListener('click', function () { analyse($('paste').value); });
    $('sample').addEventListener('click', function () {
      fetch('data/sample-report.json').then(function (r) {
        if (!r.ok) { throw new Error('HTTP ' + r.status); }
        return r.text();
      }).then(function (text) { $('paste').value = text; analyse(text); })
        .catch(function () { showError('The sample report could not be loaded.'); });
    });
    $('clear').addEventListener('click', function () {
      report = null;
      $('paste').value = '';
      $('result').hidden = true;
      $('clear').hidden = true;
      showError('');
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'), function (button) {
      button.addEventListener('click', function () {
        var target = document.querySelector(button.getAttribute('data-copy'));
        if (target) { copyText(target.textContent, button); }
      });
    });

    fetch('data/catalog.json').then(function (r) {
      if (!r.ok) { throw new Error('HTTP ' + r.status); }
      return r.json();
    }).then(function (data) {
      if (!data || !Array.isArray(data.fixes)) { throw new Error('bad catalog'); }
      catalog = data;
      data.fixes.forEach(function (fix) { if (fix && typeof fix.id === 'string') { catalogById[fix.id] = fix; } });
      $('catalog-info').textContent = 'Fix catalog: ' + data.fixes.length + ' entries, updated ' + (data.updated || 'unknown') + '.';
      renderSearchAreas();
      renderSearch();
    }).catch(function () {
      showError('The fix catalog (data/catalog.json) could not be loaded. If you opened this page as a local file, serve it from a web server instead.');
    });
  }

  document.addEventListener('DOMContentLoaded', init);
}());
