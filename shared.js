// ───────────────────────────────────────────────
// AUTHENTICATION
// Passwords are NOT stored in plain text. Each entry below is a
// SHA-256 hash of "username:password" (lowercased username).
// Viewing this code does not reveal the actual passwords.
// ───────────────────────────────────────────────
const AUTH_USERS = {
  "dmeilak":    { hash: "5a21f63471bb58837a0ebb7ae36a84f0f94099cc7549f86ca41e845c2ee45d62", role: "admin" },
  "intercomp1": { hash: "768250a208cdea4bbed22ac7e6ee3920603a1284f0be364d35e9366456d426e8", role: "user" },
  "intercomp2": { hash: "2a9920bd83bc27d815476d5a290f5bf51a8ccaf74e486b72037284ac86bf8718", role: "user" },
  "intercomp3": { hash: "b565f1486725a3d89bbf233827d16b5d6f8267608a4414d51111d310cebb17d1", role: "user" },
  "intercomp4": { hash: "cb010f41982181e2ab6c4085cdb3f8172c2f91af53ea6643639ea3e2648ab9e2", role: "user" }
};
const SESSION_KEY = 'csv_extractor_session_v1';
const REMEMBER_DURATION_MS = 60 * 24 * 60 * 60 * 1000; // 2 months

async function sha256(message) {
  const enc = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function toggleLoginPasswordVisibility() {
  const pInput = document.getElementById('login-password');
  const icon = document.getElementById('login-eye-icon');
  const btn = document.getElementById('login-eye-btn');
  const showing = pInput.type === 'text';
  pInput.type = showing ? 'password' : 'text';
  icon.className = showing ? 'ti ti-eye' : 'ti ti-eye-off';
  btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
}

// "Remember me" only makes sense — and is only offered — for the admin account.
function onLoginUsernameChange() {
  const username = document.getElementById('login-username').value.trim().toLowerCase();
  const row = document.getElementById('login-remember-row');
  const isAdmin = AUTH_USERS[username] && AUTH_USERS[username].role === 'admin';
  row.style.display = isAdmin ? 'flex' : 'none';
  if (!isAdmin) document.getElementById('login-remember-checkbox').checked = false;
}

async function attemptLogin() {
  const uInput = document.getElementById('login-username');
  const pInput = document.getElementById('login-password');
  const errorEl = document.getElementById('login-error');
  const rememberChecked = document.getElementById('login-remember-checkbox').checked;
  const username = uInput.value.trim().toLowerCase();
  const password = pInput.value;

  if (!username || !password) {
    errorEl.textContent = 'Please enter both username and password';
    errorEl.style.display = 'block';
    return;
  }

  const record = AUTH_USERS[username];
  if (!record) {
    errorEl.textContent = 'Incorrect username or password';
    errorEl.style.display = 'block';
    return;
  }

  const computedHash = await sha256(username + ':' + password);
  if (computedHash !== record.hash) {
    errorEl.textContent = 'Incorrect username or password';
    errorEl.style.display = 'block';
    return;
  }

  errorEl.style.display = 'none';
  const session = { username, role: record.role };

  // Only the admin account can be "remembered" — and only when the box is checked.
  // Remembered sessions go in localStorage with a 2-month expiry; everyone else
  // (and admin without the box checked) uses sessionStorage, cleared on tab close.
  if (record.role === 'admin' && rememberChecked) {
    const remembered = { ...session, expiresAt: Date.now() + REMEMBER_DURATION_MS };
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify(remembered));
      sessionStorage.removeItem(SESSION_KEY);
    } catch(e) {}
  } else {
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
      localStorage.removeItem(SESSION_KEY);
    } catch(e) {}
  }

  showApp(session);
}

function showApp(session) {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('main-app').style.display = 'block';
  goHome();
  document.getElementById('current-username').textContent = session.username;
  const badge = document.getElementById('current-role-badge');
  badge.textContent = session.role === 'admin' ? 'Admin' : 'User';
  badge.className = 'role-badge ' + session.role;

  // All users always use DEFAULT_RULES for processing — this ensures identical
  // results across all browsers/sessions. Admin can edit rules in the UI and
  // export the updated HTML to redeploy with new defaults.
  RULES = JSON.parse(JSON.stringify(DEFAULT_RULES));

  // Normal users do not see column mapping or weight rules panels
  const adminOnlyIds = ['mapcol-1', 'mapcol-weight', 'mapcol-2', 'mapcol-3'];
  adminOnlyIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = session.role === 'admin' ? '' : 'none';
  });

  // Threshold row visible to all users — restore saved value if present, else default 1
  const savedThresh = localStorage.getItem('csv_extractor_threshold');
  document.getElementById('threshold-input').value = savedThresh !== null ? savedThresh : '1';

  // Weight rules download button is admin-only
  const weightBtn = document.getElementById('btn-download-weight-rules');
  if (weightBtn) weightBtn.style.display = session.role === 'admin' ? 'inline-flex' : 'none';

  // Render the rule count badge for all users so it always reflects current DEFAULT_RULES.
  // RULES stays as DEFAULT_RULES for processing — admin's localStorage edits are only
  // loaded when they actively open the rules editor, not at login time.
  renderRulesUI();
}

function logout() {
  try {
    sessionStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_KEY);
  } catch(e) {}
  const mainApp = document.getElementById('main-app');
  const loginScreen = document.getElementById('login-screen');
  if (!mainApp || !loginScreen) {
    window.location.href = 'index.html';
    return;
  }
  mainApp.style.display = 'none';
  loginScreen.style.display = 'flex';
  document.getElementById('login-username').value = '';
  document.getElementById('login-password').value = '';
  document.getElementById('login-error').style.display = 'none';
  document.getElementById('login-remember-row').style.display = 'none';
  document.getElementById('login-remember-checkbox').checked = false;
  // Reset admin-only elements
  const weightBtnLogout = document.getElementById('btn-download-weight-rules');
  if (weightBtnLogout) weightBtnLogout.style.display = 'none';
}

// Restore session on page load. Checks sessionStorage first (per-tab, cleared on
// close), then localStorage (only ever set for a remembered admin session, and
// only honored if it hasn't passed its 2-month expiry).
// Deferred to DOMContentLoaded so showApp() defined in index.html is available.
function restoreSession() {
  try {
    const sessionRaw = sessionStorage.getItem(SESSION_KEY);
    if (sessionRaw) {
      const session = JSON.parse(sessionRaw);
      if (session && AUTH_USERS[session.username] && AUTH_USERS[session.username].role === session.role) {
        showApp(session);
        return;
      }
    }

    const localRaw = localStorage.getItem(SESSION_KEY);
    if (localRaw) {
      const remembered = JSON.parse(localRaw);
      const valid = remembered && AUTH_USERS[remembered.username]
        && AUTH_USERS[remembered.username].role === remembered.role
        && remembered.role === 'admin'
        && remembered.expiresAt && Date.now() < remembered.expiresAt;
      if (valid) {
        showApp({ username: remembered.username, role: remembered.role });
        return;
      } else {
        localStorage.removeItem(SESSION_KEY);
      }
    }
  } catch(e) {}
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', restoreSession);
} else {
  restoreSession();
}

const BASE_URL = 'https://intercomp.com.mt/media/catalog/product/';
const MAX_IMAGES = 5;
const OUTPUT_FIELDS = ["SKU","ITEM NAME","DESCRIPTION","PRICE","IMAGE URL 1","IMAGE URL 2","IMAGE URL 3","IMAGE URL 4","IMAGE URL 5","Stock Count","Weight","CATEGORY","SUB CATEGORY","enabled"];

// Maps internal field names to the export column header names
const EXPORT_HEADERS = {
  "SKU":           "merchant_sku",
  "ITEM NAME":     "name",
  "DESCRIPTION":   "description",
  "PRICE":         "price",
  "IMAGE URL 1":   "IMAGE URL 1",
  "IMAGE URL 2":   "IMAGE URL 2",
  "IMAGE URL 3":   "IMAGE URL 3",
  "IMAGE URL 4":   "IMAGE URL 4",
  "IMAGE URL 5":   "IMAGE URL 5",
  "Stock Count":   "number_of_units",
  "Weight":        "Weight",
  "CATEGORY":      "CATEGORY",
  "SUB CATEGORY":  "SUB CATEGORY",
  "enabled":       "enabled"
};
// Internal-only field names holding each location's stock — never written directly
// to the export; downloadCSV swaps the right one into the "Stock Count" column.
const STOCK_FIELD_PAMA = '__stock_pama__';
const STOCK_FIELD_POINT = '__stock_point__';
const ALLOWED = ["sku","name","price","description","additional_images"];
const SIMPLE_MAP = {"sku":"SKU","name":"ITEM NAME","price":"PRICE"};
const NOT_MATCHED = '__NO_MATCH__';
const STORAGE_KEY = 'csv_extractor_weight_rules_v1';

// ── Default rules (used the first time, or after Reset) ──
const DEFAULT_RULES = {
  single: ["monitor","lexmark","shark","philips","lg","gaming desk","desk","gaming chair","chair","computer case","cordless vacuum cleaner","robot vacuum cleaner","vacuum cleaner","microsoft surface","microsoft surface pro","soundbar","aoi","gaming pc","tv","acer aspire","lenovo thinkbook","lg tv","moza","ninja crispi","ninja creami","lenovo loq","simagic","ninja swirl","sony playstation 5","sony playstation 4","steering wheel","acquascooter","dell pro","air fryer","airfryer","asus vivobook","next level gaming","dell vostro","aoi master","aoi elite","aoi legend","aoi one","aoi pro","ninja slushi","ninja 3-in-1","gaming monitor","apc back ups","apc back-ups","dell latitude","apple macbook","apple imac","apple macbook air","apple macbook pro","smoothie maker","apc smart-ups","apc smart ups"],
  pairs: [["brother","printer"],["lexmark","laser"],["brother","label"],["ninja","icecream"],["ninja","drink maker"]],
  exclude: [
    "filter","toner","ink tank","cartridge",
    "fire tv stick","label printer","earbuds","rgb fan",
    "monitor cleaning kit","universal hub","cable organizer","baby monitor",
    "desk pad","surface pen","party jamboree","extension cable",
    "square labels","address labels","mousepad","gaming headset","headset",
    "remote control","apple tv","toaster","monitor backlight",
    "travel hub","gaming mouse","wrist rest","gaming mat","wireless mouse","mouse",
    "blackview shark","marshall monitor"
  ],
  // "Never set 21kg if BOTH appear" — distinct from single-word exclude:
  // these only block when the pair is present together, not on their own.
  excludePairs: [
    ["sony","controller"],
    ["sony","wireless controller"],
    ["lexmark","toner"],
    ["lextmark","tnr"],
    ["shark","tnr"],
    ["brother","tnr"],
    ["desk","fan"]
  ]
};

// Brands that must be completely excluded from the export (not just weight)
const BRAND_EXCLUSIONS = ["gree","artel"];

// TV brands used as the signal that a product IS a TV (so a 43" monitor isn't
// accidentally caught by this rule — only these brand names count).
const TV_BRANDS_FOR_SIZE_CHECK = ["lg","philips","samsung","metz"];

// Detects a screen size mentioned in the name (e.g. 43", 43 inch, 43in) and
// returns the number, or null if no size pattern is found.
function extractScreenSizeInches(name) {
  if (!name) return null;
  const match = name.match(/(\d{2,3})\s*(?:"|''|inch(?:es)?|in\b)/i);
  if (!match) return null;
  const size = parseInt(match[1], 10);
  return Number.isFinite(size) ? size : null;
}

// True if the name contains one of the TV brands AND a screen size of 43" or larger.
function isLargeBrandedTV(name) {
  if (!name) return false;
  const n = name.toLowerCase();
  const hasTVBrand = TV_BRANDS_FOR_SIZE_CHECK.some(brand => n.includes(brand));
  if (!hasTVBrand) return false;
  const size = extractScreenSizeInches(name);
  return size !== null && size >= 43;
}

// Sub Category values to silently ignore — left blank like normal, but NOT counted
// or listed in the "Unmapped Category" tab since this is an intentional skip, not a
// genuine data gap. Matched using the same normalized (space/case-insensitive) key.
function normalizeKeyEarly(s) { return String(s).toLowerCase().replace(/[^a-z0-9&]/g, ''); }
const SUBCATEGORY_SKIP_SILENTLY = ["air conditioners acs"].map(normalizeKeyEarly);

// Sub Category (lowercase) -> Parent Category (lowercase). Built from Category_Rule.xlsx,
// excluding rows where either side contains "SHOP" or "-1" (per request), with the
// TABLETS-1 sub-items remapped to "Tablets" as confirmed.
const CATEGORY_MAP = {
  "acquascooters":"water sports & equipment",
  "action cameras":"cameras",
  "air fryers":"kitchen",
  "air purifiers":"home",
  "airconditioners":"cooling & heating",
  "all in one pcs":"desktops pcs",
  "android tablets":"tablets",
  "tablets-1":"tablets",
  "androidsmartphones":"smartphones",
  "apple ipads":"tablets",
  "apple mac":"desktops pcs",
  "apple macbook":"laptops",
  "appleiphone":"smartphones",
  "arcade machines":"gaming",
  "bags & cases":"laptop accesories",
  "bathroom scales":"personal care",
  "batteries & power supplies":"laptop accesories",
  "blenders":"kitchen",
  "business laptops":"laptops",
  "cables & adaptors":"tv accesories",
  "cables & chargers":"smartphone accessories",
  "camera accesories":"photography & accessories",
  "camera accessories":"photography & accessories",
  "camera lenses":"camera accesories",
  "camera printers":"camera accesories",
  "cameras":"photography & accessories",
  "card printers":"printers, shredders & supply",
  "card readers":"desktops pcs",
  "cleaning":"home",
  "cleaning accessories":"cleaning",
  "cleaning tools & kits":"desktops pcs",
  "cleaning tools & kits-1":"cleaning",
  "laptop accesories":"laptop accesories",
  "components":"desktops pcs",
  "cooling & heating":"home",
  "corded phones":"corded/cordless phones",
  "corded/cordless phones":"smartphones&mobile",
  "cordless phones":"corded/cordless phones",
  "digital cameras":"cameras",
  "docking stations":"laptop accesories",
  "drawing tablets":"tablets",
  "drones":"cameras",
  "earbuds/earphones":"headphones",
  "external hard disks":"storage",
  "fans":"cooling & heating",
  "flight simulation":"simulation",
  "gaming chairs":"gaming",
  "gaming consoles":"gaming",
  "gaming controllers":"gaming peripherals",
  "gaming desks":"gaming",
  "gaming headphones":"gaming peripherals",
  "gaming headsets":"headphones",
  "gaming keyboards":"gaming peripherals",
  "gaming laptops":"laptops",
  "gaming mice":"gaming peripherals",
  "gaming microphones":"gaming",
  "gaming monitors":"gaming",
  "gaming pc":"gaming",
  "gaming mats":"gaming peripherals",
  "gaming pcs":"desktops pcs",
  "gaming peripherals":"gaming",
  "gaming speakers":"gaming peripherals",
  "gaming steering wheels":"simulation",
  "hairdryer":"personal care",
  "headphones":"sound & audio",
  "headset stands":"gaming peripherals",
  "headsets":"headphones",
  "heaters":"cooling & heating",
  "home printers":"printers, shredders & supply",
  "homelaptops":"laptops",
  "ice cream maker":"kitchen",
  "ink and cartridges":"printers, shredders & supply",
  "inkjet printers":"printers, shredders & supply",
  "instant cameras":"cameras",
  "keyboards":"desktops pcs",
  "kids cameras":"cameras",
  "kids smartwatches":"smartwatch & fitness trackers",
  "kids tablets":"tablets",
  "kindle":"tablets",
  "kitchen":"home",
  "label printers":"printers, shredders & supply",
  "laptop accesories":"laptop accesories",
  "laser printers":"printers, shredders & supply",
  "lg tvs":"tvs",
  "media streamers":"tv accesories",
  "metz tvs":"tvs",
  "mice":"desktops pcs",
  "mobile phones":"smartphones&mobile",
  "monitors":"desktops pcs",
  "mouse mats":"gaming peripherals",
  "network adaptors":"networking",
  "network cables":"networking",
  "office printers":"printers, shredders & supply",
  "other kitchen appliances":"kitchen",
  "pc cases":"desktops pcs",
  "pc speakers":"speakers",
  "personal care":"home",
  "philips tvs":"tvs",
  "photo frames":"cameras",
  "portable speakers":"speakers",
  "powerbanks":"smartphone accessories",
  "printer tapes":"printers, shredders & supply",
  "printer toners":"printers, shredders & supply",
  "printer ink and cartridges":"printers, shredders & supply",
  "uninterrupted-power-supplies":"uninterrupted power supplies",
  "uninterrupted power supplies":"uninterrupted power supplies",
  "projectors":"televisions (tvs)",
  "racing simulation":"simulation",
  "robot vacuum cleaners":"cleaning",
  "routers & access points":"networking",
  "rugged smartphones":"smartphones",
  "samsung tvs":"tvs",
  "scanners":"printers, shredders & supply",
  "screen protectors":"smartphone accessories",
  "sd cards":"storage",
  "shredders":"printers, shredders & supply",
  "simulation":"gaming",
  "small form factor pcs":"desktops pcs",
  "smart cameras":"cameras",
  "smart home":"home",
  "smart speakers":"speakers",
  "smart trackers":"smartphones&mobile",
  "smartphone accessories":"smartphones&mobile",
  "smartphonecases":"smartphone accessories",
  "smartphones":"smartphones&mobile",
  "smartwatch accesories":"smartwatch & fitness trackers",
  "smartwatch chargers":"smartwatch & fitness trackers",
  "smartwatch straps":"smartwatch & fitness trackers",
  "smartwatches":"smartwatch & fitness trackers",
  "software":"laptops",
  "soundbars":"soundbars",
  "soundbars-1":"soundbars",
  "speakers":"sound & audio",
  "stands & coolers":"laptop accesories",
  "stands & holders":"smartphone accessories",
  "steamers":"home",
  "storage":"camera accesories",
  "supplies":"printers, shredders & supply",
  "surface laptops":"laptops",
  "microsoft surface laptops":"laptops",
  "switches":"networking",
  "tablet accessories":"tablets",
  "tablet cases":"tablet accessories",
  "toothbrushes":"personal care",
  "tv accesories":"televisions (tvs)",
  "tv mounts":"tv accesories",
  "tv remotes":"tv accesories",
  "tvs":"televisions (tvs)",
  "usb sticks":"camera accesories",
  "vacuum cleaners":"cleaning",
  "vr headsets":"gaming peripherals",
  "webcams":"cameras",
  "wireless microphones":"sound & audio"
};

// Self-mapping: every distinct Parent Category also maps to itself, so a product
// tagged with just the broad term (e.g. Sub Category = "LAPTOPS") still resolves —
// Category: Laptops, Sub Category: Laptops. Confirmed by Damian for all parent terms.
const PARENT_SELF_MAP = {};
Object.values(CATEGORY_MAP).forEach(parent => {
  if (!(parent in CATEGORY_MAP)) PARENT_SELF_MAP[parent] = parent;
});
Object.assign(CATEGORY_MAP, PARENT_SELF_MAP);

// Strips ALL whitespace, punctuation, and case so that "SMARTPHONE CASES",
// "smartphonecases", and "Smartphone-Cases" all become the same key.
function normalizeKey(s) {
  if (!s) return '';
  return String(s).toLowerCase().replace(/[^a-z0-9&]/g, '');
}

// Pre-build a normalized version of CATEGORY_MAP so lookups during processing
// are fast and tolerant of spacing/casing/punctuation differences in the source file.
const NORMALIZED_CATEGORY_MAP = {};
Object.entries(CATEGORY_MAP).forEach(([sub, parent]) => {
  NORMALIZED_CATEGORY_MAP[normalizeKey(sub)] = parent;
});


// ── Load rules from localStorage, falling back to defaults ──
function loadRules() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && Array.isArray(parsed.single) && Array.isArray(parsed.pairs) && Array.isArray(parsed.exclude)) {
        // Older saved rules (from before excludePairs existed) won't have this key —
        // backfill it from the current defaults rather than losing the new rules.
        if (!Array.isArray(parsed.excludePairs)) {
          parsed.excludePairs = JSON.parse(JSON.stringify(DEFAULT_RULES.excludePairs));
        }
        return parsed;
      }
    }
  } catch (e) { console.warn('Could not load saved rules, using defaults', e); }
  return JSON.parse(JSON.stringify(DEFAULT_RULES));
}

function saveRules() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(RULES));
    // Also update DEFAULT_RULES in memory so the current session uses the new rules.
    // When the admin is happy with the rules, they redeploy the HTML file which has
    // the updated DEFAULT_RULES baked in for all users on all browsers/sessions.
    Object.assign(DEFAULT_RULES, JSON.parse(JSON.stringify(RULES)));
    const note = document.getElementById('rules-save-note');
    note.style.display = 'block';
    setTimeout(() => { note.style.display = 'none'; }, 2000);
  } catch (e) { console.warn('Could not save rules', e); }
  renderRulesUI();
}

let RULES = loadRules();

function renderRulesUI() {
  document.getElementById('weight-rule-count').textContent =
    RULES.single.length + RULES.pairs.length + RULES.exclude.length + (RULES.excludePairs || []).length;

  const singleGrid = document.getElementById('rules-single-grid');
  singleGrid.innerHTML = RULES.single.map((kw, i) =>
    `<span class="rule-chip">${escapeHtml(kw)}<span class="chip-remove" onclick="removeSingle(${i})">×</span></span>`
  ).join('') || '<span class="empty-state" style="padding:4px 0">No keywords yet</span>';

  const pairGrid = document.getElementById('rules-pair-grid');
  pairGrid.innerHTML = RULES.pairs.map((pair, i) =>
    `<span class="rule-chip and">${escapeHtml(pair[0])} + ${escapeHtml(pair[1])}<span class="chip-remove" onclick="removePair(${i})">×</span></span>`
  ).join('') || '<span class="empty-state" style="padding:4px 0">No pairs yet</span>';

  const excludeGrid = document.getElementById('rules-exclude-grid');
  excludeGrid.innerHTML = RULES.exclude.map((kw, i) =>
    `<span class="rule-chip exclude">${escapeHtml(kw)}<span class="chip-remove" onclick="removeExclude(${i})">×</span></span>`
  ).join('') || '<span class="empty-state" style="padding:4px 0">No exclusions yet</span>';

  const excludePairGrid = document.getElementById('rules-excludepair-grid');
  excludePairGrid.innerHTML = (RULES.excludePairs || []).map((pair, i) =>
    `<span class="rule-chip exclude">${escapeHtml(pair[0])} + ${escapeHtml(pair[1])}<span class="chip-remove" onclick="removeExcludePair(${i})">×</span></span>`
  ).join('') || '<span class="empty-state" style="padding:4px 0">No pair exclusions yet</span>';

  const brandGrid = document.getElementById('rules-brand-grid');
  brandGrid.innerHTML = BRAND_EXCLUSIONS.map(b =>
    `<span class="rule-chip brand-exclude">${escapeHtml(b.toUpperCase())}</span>`
  ).join('') || '<span class="empty-state" style="padding:4px 0">No brand exclusions</span>';
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function addSingleKeyword() {
  const input = document.getElementById('input-single');
  const val = input.value.trim().toLowerCase();
  if (!val) return;
  if (!RULES.single.includes(val)) RULES.single.push(val);
  input.value = '';
  saveRules();
}
function removeSingle(i) { RULES.single.splice(i, 1); saveRules(); }

function addPairKeyword() {
  const a = document.getElementById('input-pair-a');
  const b = document.getElementById('input-pair-b');
  const va = a.value.trim().toLowerCase(), vb = b.value.trim().toLowerCase();
  if (!va || !vb) return;
  RULES.pairs.push([va, vb]);
  a.value = ''; b.value = '';
  saveRules();
}
function removePair(i) { RULES.pairs.splice(i, 1); saveRules(); }

function addExcludePairKeyword() {
  const a = document.getElementById('input-excludepair-a');
  const b = document.getElementById('input-excludepair-b');
  const va = a.value.trim().toLowerCase(), vb = b.value.trim().toLowerCase();
  if (!va || !vb) return;
  if (!RULES.excludePairs) RULES.excludePairs = [];
  RULES.excludePairs.push([va, vb]);
  a.value = ''; b.value = '';
  saveRules();
}
function removeExcludePair(i) { RULES.excludePairs.splice(i, 1); saveRules(); }

function addExcludeKeyword() {
  const input = document.getElementById('input-exclude');
  const val = input.value.trim().toLowerCase();
  if (!val) return;
  if (!RULES.exclude.includes(val)) RULES.exclude.push(val);
  input.value = '';
  saveRules();
}
function removeExclude(i) { RULES.exclude.splice(i, 1); saveRules(); }

function resetRulesToDefault() {
  if (!confirm('Reset all weight rules back to the original defaults? This cannot be undone.')) return;
  RULES = JSON.parse(JSON.stringify(DEFAULT_RULES));
  saveRules();
}

// Escapes regex special characters in a keyword before building a boundary pattern.
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Whole-word/phrase match: "shark" matches "Shark Vacuum" but NOT "Sharkoon".
// "lg" matches "LG TV" but NOT inside "blog" or "lgentry". Works for multi-word
// phrases too ("gaming desk" requires that exact phrase, not just both words anywhere).
function containsWholeWord(haystackLower, keywordLower) {
  if (!keywordLower) return false;
  const pattern = new RegExp('(?:^|[^a-z0-9])' + escapeRegex(keywordLower) + '(?:$|[^a-z0-9])', 'i');
  return pattern.test(haystackLower);
}

function determineWeight(name) {
  if (!name) return { weight: '', reason: null, excluded: false };
  const n = name.toLowerCase();
  const hasExclusion = RULES.exclude.some(kw => containsWholeWord(n, kw));
  const hasExcludePair = (RULES.excludePairs || []).some(([a, b]) => containsWholeWord(n, a) && containsWholeWord(n, b));
  let matchedRule = null;
  for (const kw of RULES.single) {
    if (containsWholeWord(n, kw)) { matchedRule = kw; break; }
  }
  if (!matchedRule) {
    for (const [a, b] of RULES.pairs) {
      if (containsWholeWord(n, a) && containsWholeWord(n, b)) { matchedRule = `${a} + ${b}`; break; }
    }
  }
  if (matchedRule && (hasExclusion || hasExcludePair)) return { weight: '', reason: matchedRule, excluded: true };
  if (matchedRule) return { weight: '21', reason: matchedRule, excluded: false };
  return { weight: '', reason: null, excluded: false };
}

let extractedRows = [], weightedRows = [], excludedRows = [], step1Done = false;

// Per-location state — each location (pama / point) tracks its own matched
// SKU->qty map, its list of "in their file but not in Magento" entries, and
// whether it has completed at least once. Two independent imports, two
// independent exports — neither affects the other.
const LOCATIONS = {
  pama:  { label: 'Pama Shopping Mall',     stockField: STOCK_FIELD_PAMA,  stockMap: {}, unmatched: [], done: false, fileName: '' },
  point: { label: 'The Point Shopping Mall', stockField: STOCK_FIELD_POINT, stockMap: {}, unmatched: [], done: false, fileName: '' }
};

function toggleMapping(id) {
  document.getElementById(id).classList.toggle('open');
  // When admin opens the weight rules panel, load their saved rules into RULES
  // for editing. This keeps RULES as DEFAULT_RULES for processing until the
  // admin explicitly opens the editor.
  if (id === 'mapcol-weight' && document.getElementById(id).classList.contains('open')) {
    const savedRules = loadRules();
    Object.assign(RULES, savedRules);
    renderRulesUI();
  }
}

function setProgress(n, pct, step, label) {
  const sep = typeof n === 'number' ? '' : '-';
  document.getElementById(`load${sep}${n}-fill`).style.width = pct + '%';
  document.getElementById(`load${sep}${n}-pct`).textContent = Math.round(pct) + '%';
  document.getElementById(`load${sep}${n}-label`).textContent = label || (pct < 100 ? 'Processing…' : 'Complete');
  if (step) document.getElementById(`load${sep}${n}-step`).textContent = step;
}

function parseAllRows(text) {
  const rows = []; let i = 0, len = text.length;
  while (i < len) {
    const row = [];
    while (i < len) {
      if (text[i] === '"') {
        i++; let f = '';
        while (i < len) {
          if (text[i] === '"') { if (text[i+1]==='"') { f+='"'; i+=2; } else { i++; break; } }
          else f += text[i++];
        }
        row.push(f);
        if (text[i]===',') i++;
        else if (text[i]==='\r') { i++; if(text[i]==='\n') i++; break; }
        else if (text[i]==='\n') { i++; break; }
        else if (i>=len) break;
      } else {
        let f = '';
        while (i<len && text[i]!==',' && text[i]!=='\n' && text[i]!=='\r') f+=text[i++];
        row.push(f.trim());
        if (text[i]===',') i++;
        else if (text[i]==='\r') { i++; if(text[i]==='\n') i++; break; }
        else if (text[i]==='\n') { i++; break; }
        else if (i>=len) break;
      }
    }
    if (row.length > 0) rows.push(row);
  }
  return rows;
}

function parseXLSX(buffer) {
  if (typeof XLSX === 'undefined') {
    throw new Error('Excel reader failed to load. Refresh the page and try again.');
  }
  const wb = XLSX.read(buffer, { type: 'array' });
  const ws = wb.Sheets[wb.SheetNames[0]];
  return XLSX.utils.sheet_to_json(ws, { header: 1, defval: null, raw: true });
}

// String-safe parser for files where SKUs must be preserved exactly as text
// (e.g. long numeric SKUs that would lose precision if parsed as JS numbers).

function forceText(val) {
  if (val === null || val === undefined || val === '') return '';
  if (typeof val === 'number') {
    if (Number.isFinite(val)) return String(Math.round(val));
    return '';
  }
  const s = String(val).trim();
  if (!s) return '';
  if (/^-?\d+\.?\d*[eE][+\-]?\d+$/.test(s)) {
    try { return String(BigInt(Math.round(parseFloat(s)))); } catch(e) { return s; }
  }
  if (/^-?\d+\.0+$/.test(s)) return String(Math.round(parseFloat(s)));
  return s;
}

// ───────────────────────────────────────────────
// ITEM NAME formatting — ported directly from titlefixer.html so product
// names go from ALL CAPS to properly cased titles (e.g. "iPhone", "OLED",
// "256GB"), matching exactly what that standalone tool produces.
// ───────────────────────────────────────────────
const TITLE_EX = {iphone:'iPhone',ipad:'iPad',macbook:'MacBook',airpods:'AirPods',airtag:'AirTag',imac:'iMac',ipod:'iPod',arcade1up:'Arcade1Up',insta360:'Insta360',sandisk:'SanDisk',playstation:'PlayStation','tp-link':'TP-Link','joy-con':'Joy-Con',powerstore:'PowerStore',w10pro:'W10Pro',w11pro:'W11Pro',microsd:'MicroSD',myfirst:'myFirst'};
const TITLE_UP = new Set(['wqhd','fhd','oled','hd','qned','hz','led','ips','rtx','mp','ssd','rgb','mm','rs','x5','x3','usb-c','aoi','linq','moza','oppo','simagic','trunk','ugreen','zagg','amoled','xbox','ps5','ps4','apc','hdd','ryzen','lego','jbl','wlan','emc','lg','uk','w11p','w10p','5g','4g','lte']);
const TITLE_MR = /^\d+(\.\d+)?m$/i;
// Apple product suffixes that should be title-cased (not all-caps, not all-lower)
const TITLE_APPLE_SUFFIX = new Set(['pro','max','mini','air','plus','ultra']);

function titleFixWord(w) {
  if (!w) return w;
  const l = w.toLowerCase();
  if (TITLE_EX[l]) return TITLE_EX[l];
  if (TITLE_UP.has(l)) return l.toUpperCase();
  if (TITLE_MR.test(l)) return l.toUpperCase();
  // Apple product suffixes — always title-cased (e.g. "Pro", "Max", "Mini")
  if (TITLE_APPLE_SUFFIX.has(l)) return l.charAt(0).toUpperCase() + l.slice(1);
  if (/^\d+gb$/i.test(w)) return w.replace(/gb$/i, 'GB');
  if (/^gb$/i.test(w)) return 'GB';
  if (/^\d+tb$/i.test(w)) return w.replace(/tb$/i, 'TB');
  if (/^tb$/i.test(w)) return 'TB';
  return w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
}

function titleFixName(raw) {
  if (!raw) return '';
  let s = raw.trim().replace(/\//g, ' | ').replace(/ {2,}/g, ' ');
  s = s.split(' ').map(w => w === '|' ? '|' : titleFixWord(w)).join(' ');
  return s.replace(/\s*\|\s*/g, ' | ');
}

function cleanDescription(raw) {
  if (!raw) return '';
  let s = String(raw);
  s = s.replace(/<br\s*\/?>/gi, '\n');
  s = s.replace(/<[^>]*>/g, '');
  s = s.replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  s = s.split('\n').map(line => line.trim()).join('\n');
  s = s.replace(/\n{3,}/g, '\n\n').trim();
  return s;
}

function sortByStock(rows, stockField) {
  const field = stockField || 'Stock Count';
  return [...rows].sort((a, b) => {
    const aVal = a[field], bVal = b[field];
    const aNum = aVal === '' ? -Infinity : (parseFloat(aVal) ?? 0);
    const bNum = bVal === '' ? -Infinity : (parseFloat(bVal) ?? 0);
    return bNum - aNum;
  });
}

function buildImageURLs(raw) {
  if (!raw || !String(raw).trim()) return {};
  const urls = {};
  String(raw).split(',').map(p=>p.trim()).filter(Boolean).slice(0,MAX_IMAGES).forEach((p,i) => {
    urls[`IMAGE URL ${i+1}`] = BASE_URL + p.replace(/^\/+/,'');
  });
  return urls;
}

function initDZ1() {
  const dz1 = document.getElementById('dz1'), fi1 = document.getElementById('fi1');
  if (!dz1||!fi1) return;
  dz1.addEventListener('dragover', e => { e.preventDefault(); dz1.classList.add('drag-over'); });
  dz1.addEventListener('dragleave', () => dz1.classList.remove('drag-over'));
  dz1.addEventListener('drop', e => { e.preventDefault(); dz1.classList.remove('drag-over'); handleStep1(e.dataTransfer.files[0]); });
  fi1.addEventListener('change', e => handleStep1(e.target.files[0]));
}
initDZ1();
if (document.getElementById('weight-rule-count')) renderRulesUI();

function handleStep1(file) {
  if (!file) return;
  document.getElementById('load1').style.display = 'block';
  setProgress(1, 5, 'Reading file…');
  const reader = new FileReader();
  reader.onload = e => { setProgress(1, 25, 'Parsing rows…'); setTimeout(() => processStep1(e.target.result, file.name), 30); };
  reader.readAsText(file);
}

function processStep1(text, fname) {
  setProgress(1, 40, 'Detecting columns…');
  const allRows = parseAllRows(text);
  if (allRows.length < 2) return;
  const headers = allRows[0].map(h => String(h||'').toLowerCase().trim());
  const colIdx = {};
  ALLOWED.forEach(col => { const i = headers.indexOf(col); if (i !== -1) colIdx[col] = i; });
  setProgress(1, 60, 'Mapping fields…');

  weightedRows = []; excludedRows = [];
  let brandExcludedCount = 0;
  let zeroPriceExcludedCount = 0;
  let demoExcludedCount = 0;
  let largeTvExcludedCount = 0;

  // DEBUG: log RULES state so we can compare admin vs user
  console.log('[DEBUG] RULES at Step1 processing:', JSON.stringify({
    single: RULES.single.length,
    pairs: RULES.pairs.length,
    exclude: RULES.exclude.length,
    excludePairs: (RULES.excludePairs||[]).length,
    singleSample: RULES.single.slice(0,3)
  }));

  extractedRows = allRows.slice(1).map(vals => {
    const src = {};
    ALLOWED.forEach(col => { if (colIdx[col] !== undefined) src[col] = vals[colIdx[col]]; });
    const out = {};
    OUTPUT_FIELDS.forEach(f => out[f] = '');
    Object.entries(SIMPLE_MAP).forEach(([sk,df]) => {
      out[df] = df === 'SKU' ? forceText(src[sk]) : (src[sk] ? String(src[sk]) : '');
    });
    out['DESCRIPTION'] = cleanDescription(src['description'] || '');
    Object.assign(out, buildImageURLs(src['additional_images']||''));
    out['Stock Count'] = NOT_MATCHED;
    out[STOCK_FIELD_PAMA] = NOT_MATCHED;
    out[STOCK_FIELD_POINT] = NOT_MATCHED;

    const nameVal = out['ITEM NAME'];
    const wResult = determineWeight(nameVal);
    out['Weight'] = wResult.weight;
    if (wResult.weight === '21') weightedRows.push({ sku: out['SKU'], name: nameVal, rule: wResult.reason });
    if (wResult.excluded) excludedRows.push({ sku: out['SKU'], name: nameVal, rule: wResult.reason });

    return out;
  }).filter(r => r['SKU'])
    .filter(r => {
      const isBrandExcluded = BRAND_EXCLUSIONS.some(brand => (r['ITEM NAME'] || '').toLowerCase().includes(brand));
      if (isBrandExcluded) brandExcludedCount++;
      return !isBrandExcluded;
    })
    .filter(r => {
      // Remove products with no price or a price of 0 — never export them.
      const priceNum = parseFloat(r['PRICE']);
      const isZeroPrice = !r['PRICE'] || isNaN(priceNum) || priceNum === 0;
      if (isZeroPrice) zeroPriceExcludedCount++;
      return !isZeroPrice;
    })
    .filter(r => {
      // Remove anything with "demo" in the name.
      const isDemo = (r['ITEM NAME'] || '').toLowerCase().includes('demo');
      if (isDemo) demoExcludedCount++;
      return !isDemo;
    })
    .filter(r => {
      // Remove LG/Philips/Samsung/Metz TVs that are 43" or larger.
      const isLargeTv = isLargeBrandedTV(r['ITEM NAME']);
      if (isLargeTv) largeTvExcludedCount++;
      return !isLargeTv;
    });

  // Fix UTF-8/Latin-1 encoding corruption FIRST (e.g. "AirpodsÂ Pro" → "Airpods Pro"),
  // then apply title casing — order matters because titleFixName splits on spaces, and
  // the Â corruption binds to the preceding word, so cleaning it first ensures the
  // title-caser sees clean text. Also clean DESCRIPTION at the same time.
  extractedRows.forEach(r => {
    r['ITEM NAME'] = titleFixName(fixEncoding(r['ITEM NAME']));
    if (r['DESCRIPTION']) r['DESCRIPTION'] = fixEncoding(r['DESCRIPTION']);
  });

  window.__lastBrandExcludedCount = brandExcludedCount;

  setProgress(1, 100, 'Done!', 'Complete');
  step1Done = true;
  setTimeout(() => {
    document.getElementById('load1').style.display = 'none';
    document.getElementById('s1-dropwrap').innerHTML = `<div class="dz-done-bar"><i class="ti ti-circle-check"></i><span>${fname} — ${extractedRows.length} products loaded${brandExcludedCount > 0 ? ` (${brandExcludedCount} GREE/ARTEL excluded)` : ''}${zeroPriceExcludedCount > 0 ? ` (${zeroPriceExcludedCount} zero-price excluded)` : ''}${demoExcludedCount > 0 ? ` (${demoExcludedCount} demo excluded)` : ''}${largeTvExcludedCount > 0 ? ` (${largeTvExcludedCount} large TVs excluded)` : ''}</span><button onclick="resetStep1()">Change</button></div>`;
    document.getElementById('s1-num').className = 'step-num done';
    document.getElementById('s1-badge').textContent = '✓ Done';
    document.getElementById('s1-badge').className = 'step-badge done';
    unlockStep2();
  }, 400);
}

function unlockStep2() {
  document.getElementById('s2-num').className = 'step-num';
  document.getElementById('s2-title').className = 'step-title';
  document.getElementById('s2-badge').textContent = 'Ready';
  document.getElementById('s2-badge').className = 'step-badge pending';
  document.getElementById('location-note').style.display = 'block';
  unlockLocation('pama');
  unlockLocation('point');
}

// Unlocks one location's upload zone (Pama or The Point). Both can be done
// independently, in either order, in the same session.
function unlockLocation(loc) {
  const info = LOCATIONS[loc];
  const dropwrap = document.getElementById(`${loc}-dropwrap`);
  dropwrap.innerHTML = `
    <div class="drop-zone" id="dz-${loc}" onclick="document.getElementById('fi-${loc}').click()">
      <div class="dz-cloud"><i class="ti ti-cloud-upload"></i></div>
      <div class="dz-title">${info.label}</div>
      <div class="dz-sub">Drag &amp; Drop your Inventory Valuation file<br>.xlsx · Col A = Item No. &nbsp;·&nbsp; Col P = Quantity</div>
      <input type="file" id="fi-${loc}" accept=".xlsx,.xls,.csv">
    </div>`;
  const dz = document.getElementById(`dz-${loc}`), fi = document.getElementById(`fi-${loc}`);
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('drag-over'); handleLocationFile(loc, e.dataTransfer.files[0]); });
  fi.addEventListener('change', e => handleLocationFile(loc, e.target.files[0]));
}

function handleLocationFile(loc, file) {
  if (!file || !step1Done) return;
  document.getElementById(`load-${loc}`).style.display = 'block';
  setProgress(loc, 5, `Reading ${LOCATIONS[loc].label} file…`);
  readLocationFile(loc, file);
}

function readLocationFile(loc, file) {
  setProgress(loc, 15, 'Reading Excel file…');
  const reader = new FileReader();
  reader.onload = e => { setProgress(loc, 35, 'Parsing rows…'); setTimeout(() => processLocationFile(loc, e.target.result, file.name), 30); };
  reader.readAsArrayBuffer(file);
}

function processLocationFile(loc, buffer, fname) {
  const info = LOCATIONS[loc];
  setProgress(loc, 50, 'Reading columns…');
  let allRows;
  try { allRows = parseXLSX(buffer); } catch(e) { document.getElementById(`load-${loc}-step`).textContent = 'Error: ' + e.message; return; }

  info.stockMap = {}; info.unmatched = [];
  const productSKUs = new Set(extractedRows.map(r => r['SKU']));

  allRows.forEach((row) => {
    const colA = row[0];
    const colB = row[1]; // Item name/description — only used for "Not in Magento" export
    const colP = row[15];
    if (typeof colP !== 'number') return;
    const rawSku = forceText(colA);
    if (!rawSku) return;
    const qty = forceText(colP) || '0';
    const itemName = colB ? fixEncoding(String(colB).trim()) : '';
    info.stockMap[rawSku] = qty;
    if (!productSKUs.has(rawSku)) info.unmatched.push({ sku: rawSku, qty, name: itemName });
  });

  setProgress(loc, 75, 'Matching SKUs…');
  let matched = 0;
  extractedRows.forEach(row => {
    const sku = row['SKU'];
    if (sku && Object.prototype.hasOwnProperty.call(info.stockMap, sku)) {
      row[info.stockField] = info.stockMap[sku];
      matched++;
    }
    if (row[info.stockField] === NOT_MATCHED) row[info.stockField] = '';
  });

  info.unmatched.sort((a, b) => (parseFloat(b.qty) || 0) - (parseFloat(a.qty) || 0));

  setProgress(loc, 100, `Matched ${matched} of ${extractedRows.length} SKUs`, 'Complete');
  setTimeout(() => {
    document.getElementById(`load-${loc}`).style.display = 'none';
    document.getElementById(`${loc}-dropwrap`).innerHTML = `<div class="dz-done-bar"><i class="ti ti-circle-check"></i><span>${fname} — ${matched} SKUs matched</span><button onclick="resetLocation('${loc}')">Change</button></div>`;
    info.done = true;
    info.fileName = fname;
    maybeUnlockStep3();
    if (Object.values(LOCATIONS).some(l => l.done)) renderResults();

    // Pulse the threshold row after first location upload to draw attention to it
    const threshRow = document.getElementById('threshold-row');
    if (threshRow) {
      threshRow.classList.remove('pulse');
      void threshRow.offsetWidth;
      threshRow.classList.add('pulse');
      setTimeout(() => threshRow.classList.remove('pulse'), 2200);
    }
  }, 400);
}

// Step 3 (Category Import) unlocks as soon as AT LEAST ONE location is done —
// the user doesn't need to do both before moving on.
function maybeUnlockStep3() {
  if (Object.values(LOCATIONS).some(l => l.done) && !step2AnyDone) {
    step2AnyDone = true;
    unlockStep3();
  }
}
let step2AnyDone = false;

function resetLocation(loc) {
  const info = LOCATIONS[loc];
  info.stockMap = {}; info.unmatched = []; info.done = false; info.fileName = '';
  extractedRows.forEach(r => { r[info.stockField] = ''; });
  document.getElementById(`load-${loc}`).style.display = 'none';
  unlockLocation(loc);
  if (Object.values(LOCATIONS).some(l => l.done)) renderResults();
}

// Removes a trailing "-1" from Category/Sub Category text only (e.g. "Soundbars-1"
// -> "Soundbars"). Deliberately NOT applied anywhere else, since "-1" can be a
// meaningful part of a real SKU and must never be touched there.
function stripDash1(s) {
  if (!s) return s;
  return s.replace(/-1\b/g, '');
}

// ── Title-case helper for Category/Sub Category, e.g. "ACTION CAMERAS" -> "Action Cameras" ──
// Also fixes known acronyms (SD, USB, PC, PCs, TV, TVs, VR, LG) to their correct casing
// instead of plain title-case (which would give "Sd", "Usb", "Pc", "Tv", etc.), and
// renames "Desktops" -> "Desktop" specifically before "PCs" per Damian's correction.
const ACRONYM_FIXES = {
  'sd': 'SD',
  'usb': 'USB',
  'pc': 'PC',
  'pcs': 'PCs',
  'tv': 'TV',
  'tvs': 'TVs',
  'vr': 'VR',
  'lg': 'LG',
  'ups': 'UPS'
};

function titleCase(s) {
  if (!s) return '';
  let result = s.toLowerCase().replace(/\b\w/g, c => c.toUpperCase());

  // Apply acronym fixes word-by-word (case-insensitive, whole word only)
  result = result.split(' ').map(word => {
    // Strip trailing punctuation (e.g. "Cards," ) for matching, keep it on output
    const bare = word.replace(/[^a-zA-Z]/g, '');
    const fixed = ACRONYM_FIXES[bare.toLowerCase()];
    if (fixed) return word.replace(new RegExp(bare, 'i'), fixed);
    return word;
  }).join(' ');

  // "Desktops PCs" -> "Desktop PCs" (singular, per confirmed correction)
  result = result.replace(/\bDesktops PCs\b/i, 'Desktop PCs');

  // Add spaces around "&" when missing, e.g. "Smartphones&Mobile" -> "Smartphones & Mobile"
  result = result.replace(/(\S)&(\S)/g, '$1 & $2');

  return result;
}

function unlockStep3() {
  document.getElementById('s3-num').className = 'step-num';
  document.getElementById('s3-title').className = 'step-title';
  document.getElementById('s3-badge').textContent = 'Ready';
  document.getElementById('s3-badge').className = 'step-badge pending';
  document.getElementById('s3-dropwrap').innerHTML = `
    <div class="drop-zone" id="dz3" onclick="document.getElementById('fi3').click()">
      <div class="dz-cloud"><i class="ti ti-cloud-upload"></i></div>
      <div class="dz-title">Category Import</div>
      <div class="dz-sub">Drag &amp; Drop your category file<br>Col D = SKU &nbsp;·&nbsp; Col B = Sub Category &nbsp;·&nbsp; from row 4</div>
      <input type="file" id="fi3" accept=".xlsx,.xls,.csv">
    </div>`;
  const dz3 = document.getElementById('dz3'), fi3 = document.getElementById('fi3');
  dz3.addEventListener('dragover', e => { e.preventDefault(); dz3.classList.add('drag-over'); });
  dz3.addEventListener('dragleave', () => dz3.classList.remove('drag-over'));
  dz3.addEventListener('drop', e => { e.preventDefault(); dz3.classList.remove('drag-over'); handleStep3(e.dataTransfer.files[0]); });
  fi3.addEventListener('change', e => handleStep3(e.target.files[0]));
}

function handleStep3(file) {
  if (!file||!step1Done) return;
  document.getElementById('load3').style.display = 'block';
  setProgress(3, 5, 'Reading category file…');
  readStep3File(file);
}

function readStep3File(file) {
  setProgress(3, 15, 'Reading Excel file…');
  const reader = new FileReader();
  reader.onload = e => { setProgress(3, 35, 'Parsing rows…'); setTimeout(() => processStep3(e.target.result, file.name), 30); };
  reader.readAsArrayBuffer(file);
}

let uncategorizedRows = [];

function processStep3(buffer, fname) {
  setProgress(3, 50, 'Reading columns…');
  let allRows;
  try { allRows = parseXLSX(buffer); } catch(e) { document.getElementById('load3-step').textContent = 'Error: ' + e.message; return; }

  // Col B = index 1 (Sub Category), Col D = index 3 (SKU). Data starts at row 4 (index 3).
  const subCategoryMap = {};
  allRows.forEach((row, i) => {
    if (i < 3) return; // skip header rows 1-3
    const rawSku = forceText(row[3]);
    const rawSub = row[1] !== null && row[1] !== undefined ? String(row[1]).trim() : '';
    if (!rawSku || !rawSub) return;
    subCategoryMap[rawSku] = rawSub;
  });

  setProgress(3, 75, 'Matching categories…');
  let categorized = 0;
  uncategorizedRows = [];
  const shopExcludedSKUs = new Set();

  extractedRows.forEach(row => {
    const sku = row['SKU'];
    const rawSub = subCategoryMap[sku];
    if (!rawSub) return; // no category data for this SKU at all

    // If the Sub Category contains "SHOP", the entire product is removed from the
    // export (same treatment as GREE/ARTEL brand exclusions), not just left blank.
    if (rawSub.toLowerCase().includes('shop')) {
      shopExcludedSKUs.add(sku);
      return;
    }

    // Normalize: lowercase + strip ALL whitespace/punctuation so "SMARTPHONE CASES",
    // "smartphonecases", and "Smartphone-Cases" all resolve to the same lookup key.
    const subKey = normalizeKey(rawSub);

    // Intentionally-ignored sub categories (e.g. "Air Conditioners ACS") — blank,
    // but not counted or shown in the Unmapped Category tab.
    if (SUBCATEGORY_SKIP_SILENTLY.includes(subKey)) {
      row['SUB CATEGORY'] = '';
      row['CATEGORY'] = '';
      return;
    }

    const parentLower = NORMALIZED_CATEGORY_MAP[subKey];

    if (parentLower) {
      row['SUB CATEGORY'] = titleCase(stripDash1(rawSub));
      row['CATEGORY'] = titleCase(stripDash1(parentLower));
      categorized++;
    } else {
      // Sub category present but not in our lookup table — leave both blank, track it
      row['SUB CATEGORY'] = '';
      row['CATEGORY'] = '';
      uncategorizedRows.push({ sku, name: row['ITEM NAME'], subCategory: rawSub });
    }
  });

  let shopExcludedCount = 0;
  if (shopExcludedSKUs.size > 0) {
    const before = extractedRows.length;
    extractedRows = extractedRows.filter(r => !shopExcludedSKUs.has(r['SKU']));
    shopExcludedCount = before - extractedRows.length;
  }

  setProgress(3, 100, `Matched ${categorized} categories, ${uncategorizedRows.length} unmapped${shopExcludedCount > 0 ? `, ${shopExcludedCount} removed (SHOP)` : ''}`, 'Complete');
  setTimeout(() => {
    document.getElementById('load3').style.display = 'none';
    document.getElementById('s3-dropwrap').innerHTML = `<div class="dz-done-bar"><i class="ti ti-circle-check"></i><span>${fname} — ${categorized} categorized${uncategorizedRows.length > 0 ? `, ${uncategorizedRows.length} unmapped` : ''}${shopExcludedCount > 0 ? `, ${shopExcludedCount} removed (SHOP)` : ''}</span><button onclick="resetStep3()">Change</button></div>`;
    document.getElementById('s3-num').className = 'step-num done';
    document.getElementById('s3-badge').textContent = '✓ Done';
    document.getElementById('s3-badge').className = 'step-badge done';
    renderResults();
  }, 400);
}

function resetStep3(lock) {
  document.getElementById('load3').style.display = 'none';
  document.getElementById('s3-num').className = lock ? 'step-num locked' : 'step-num';
  document.getElementById('s3-title').className = lock ? 'step-title locked' : 'step-title';
  document.getElementById('s3-badge').textContent = lock ? 'Locked' : 'Ready';
  document.getElementById('s3-badge').className = 'step-badge pending';
  if (lock) {
    document.getElementById('s3-dropwrap').innerHTML = `<div class="drop-zone locked-zone" id="dz3"><div class="dz-cloud"><i class="ti ti-lock"></i></div><div class="dz-title">Complete Step 2 first</div><div class="dz-sub">This does not need to be uploaded always</div></div>`;
  } else {
    extractedRows.forEach(r => { r['CATEGORY'] = ''; r['SUB CATEGORY'] = ''; });
    uncategorizedRows = [];
    unlockStep3();
  }
}

let activeLocationView = 'pama';

function setActiveLocationView(loc) {
  activeLocationView = loc;
  document.getElementById('loc-toggle-pama').className = 'loc-toggle-btn' + (loc === 'pama' ? ' active' : '');
  document.getElementById('loc-toggle-point').className = 'loc-toggle-btn' + (loc === 'point' ? ' active' : '');
  renderResults();
}

function renderResults() {
  const loc = activeLocationView;
  const info = LOCATIONS[loc];
  const stockField = info.stockField;

  // If this location hasn't been uploaded yet, show a clear placeholder
  // instead of rendering misleading empty/zero results
  if (!info.done) {
    document.getElementById('table-head').innerHTML = '';
    document.getElementById('table-body').innerHTML = `<tr><td colspan="13" style="text-align:center;padding:2rem;color:#9a9690;font-style:italic">${info.label} file not yet uploaded — upload it in Step 2 above to see results here.</td></tr>`;
    document.getElementById('stat-total').textContent = '—';
    document.getElementById('stat-stock').textContent = '—';
    document.getElementById('stat-unmatched').textContent = '—';
    document.getElementById('count-notinpama').textContent = '0';
    document.getElementById('count-notinmagento').textContent = '0';
    document.getElementById('nostock-list').innerHTML = `<div class="empty-state">${info.label} not yet uploaded.</div>`;
    document.getElementById('unmatched-list').innerHTML = `<div class="empty-state">${info.label} not yet uploaded.</div>`;
    document.getElementById('btn-export-notinmagento').style.display = 'none';
    document.getElementById('results-section').style.display = 'block';
    document.getElementById('btn-download-pama').style.display = LOCATIONS.pama.done ? 'inline-flex' : 'none';
    document.getElementById('btn-download-point').style.display = LOCATIONS.point.done ? 'inline-flex' : 'none';
    return;
  }

  // Update labels that mention the active location by name
  document.getElementById('unmatched-loc-name').textContent = info.label;
  document.getElementById('notinmagento-loc-name').textContent = info.label;
  document.getElementById('tab-unmatched-loc').textContent = info.label.replace(' Shopping Mall', '');
  document.getElementById('stat-unmatched').parentElement.querySelector('.stat-lbl').textContent = `Not in ${info.label.replace(' Shopping Mall', '')}`;

  const head = document.getElementById('table-head'), body = document.getElementById('table-body');
  head.innerHTML = OUTPUT_FIELDS.map(f => `<th>${EXPORT_HEADERS[f] || f}</th>`).join('');
  body.innerHTML = '';

  const sortedRows = sortByStock(extractedRows, stockField);
  const threshold = getThreshold();

  // Show matched rows first (sorted by stock), then unmatched at the bottom
  const previewMatched = sortedRows.filter(r => r[stockField] !== '' && r[stockField] !== NOT_MATCHED && r[stockField] !== undefined && r[stockField] !== null);
  const previewUnmatched = sortedRows.filter(r => r[stockField] === '' || r[stockField] === NOT_MATCHED || r[stockField] === undefined || r[stockField] === null);
  const allPreviewRows = [...previewMatched, ...previewUnmatched];

  allPreviewRows.forEach(row => {
    const isUnmatched = row[stockField] === '' || row[stockField] === NOT_MATCHED || row[stockField] === undefined || row[stockField] === null;
    const tr = document.createElement('tr');
    if (isUnmatched) tr.style.opacity = '0.5';
    OUTPUT_FIELDS.forEach(f => {
      const td = document.createElement('td');
      const val = f === 'Stock Count' ? (row[stockField] ?? '') : (row[f] ?? '');
      if (f === 'enabled') {
        if (isUnmatched) { td.textContent = 'FALSE'; td.className = 'stock-zero'; }
        else {
          const stockNum = parseFloat(row[stockField]);
          const enabled = threshold !== null && !isNaN(stockNum) && stockNum >= threshold;
          td.textContent = enabled ? 'TRUE' : 'FALSE';
          td.className = enabled ? 'stock-filled' : 'stock-zero';
        }
      } else if (f === 'Stock Count') {
        if (isUnmatched) { td.textContent = '0'; td.className = 'stock-zero'; }
        else if (val === '0') { td.textContent = '0'; td.className = 'stock-zero'; }
        else { td.textContent = val; td.className = 'stock-filled'; }
      } else if (f === 'DESCRIPTION') {
        td.textContent = val ? val.split('\n')[0] : '—';
        if (!val) td.className = 'empty';
        td.title = val;
      } else if (f === 'Weight') {
        if (val === '21') { td.textContent = '21kg'; td.className = 'weight-set'; }
        else { td.textContent = '—'; td.className = 'empty'; }
      } else if (f === 'CATEGORY' || f === 'SUB CATEGORY') {
        if (val) { td.textContent = val; td.className = 'category-set'; }
        else { td.textContent = '—'; td.className = 'empty'; }
      } else if (!val) { td.textContent = '—'; td.className = 'empty'; }
      else if (f.startsWith('IMAGE URL')) { td.textContent = val; td.className = 'url'; td.title = val; }
      else td.textContent = val;
      tr.appendChild(td);
    });
    body.appendChild(tr);
  });

  const total = extractedRows.length;
  const withStock = extractedRows.filter(r => r[stockField] !== '' && r[stockField] !== NOT_MATCHED).length;
  const notInLoc = total - withStock;
  const notInMagento = info.unmatched.length;

  document.getElementById('stat-total').textContent = total.toLocaleString();
  document.getElementById('stat-stock').textContent = withStock.toLocaleString();
  document.getElementById('stat-unmatched').textContent = notInLoc.toLocaleString();
  document.getElementById('count-notinpama').textContent = notInLoc.toLocaleString();
  document.getElementById('count-notinmagento').textContent = notInMagento.toLocaleString();
  document.getElementById('stat-weighted').textContent = weightedRows.length.toLocaleString();
  document.getElementById('stat-excluded').textContent = excludedRows.length.toLocaleString();
  document.getElementById('count-weighted').textContent = weightedRows.length.toLocaleString();

  const ns = document.getElementById('nostock-list');
  const noStockRows = extractedRows.filter(r => r[stockField] === '' || r[stockField] === NOT_MATCHED);
  ns.innerHTML = noStockRows.length === 0
    ? `<div class="empty-state">All products matched in ${info.label} ✓</div>`
    : noStockRows.slice(0,200).map(r => `<div class="result-pill unmatched"><span class="rp-sku">${r['SKU']}</span><span class="rp-name">${r['ITEM NAME']||''}</span><span class="rp-miss">Not in ${info.label.replace(' Shopping Mall','')}</span></div>`).join('')
      + (noStockRows.length > 200 ? `<div class="empty-state">…and ${noStockRows.length-200} more</div>` : '');

  const ul = document.getElementById('unmatched-list');
  const exportBtn = document.getElementById('btn-export-notinmagento');
  if (info.unmatched.length === 0) {
    ul.innerHTML = `<div class="empty-state">All ${info.label} SKUs found in Magento import ✓</div>`;
    exportBtn.style.display = 'none';
  } else {
    exportBtn.style.display = 'inline-flex';
    ul.innerHTML = info.unmatched.slice(0,200).map(p => {
      const qtyNum = parseFloat(p.qty) || 0;
      const stockClass = qtyNum > 0 ? 'rp-stock' : 'rp-zero';
      // SKUs in "Not in Magento" are by definition NOT in extractedRows, so no title available
      return `<div class="result-pill ${qtyNum > 0 ? 'matched' : 'zero'}"><span class="rp-sku">${p.sku}</span><span class="${stockClass}">${p.qty}</span></div>`;
    }).join('') + (info.unmatched.length > 200 ? `<div class="empty-state">…and ${info.unmatched.length-200} more (included in export)</div>` : '');
  }

  const wl = document.getElementById('weighted-list');
  wl.innerHTML = weightedRows.length === 0
    ? '<div class="empty-state">No products matched a 21kg rule</div>'
    : weightedRows.slice(0,200).map(w => `<div class="result-pill weighted"><span class="rp-sku">${w.sku}</span><span class="rp-name">${w.name}</span><span class="rp-weight">21kg</span></div>`).join('')
      + (weightedRows.length > 200 ? `<div class="empty-state">…and ${weightedRows.length-200} more</div>` : '');

  // Category stats
  const categorized = extractedRows.filter(r => r['CATEGORY']).length;
  document.getElementById('stat-categorized').textContent = categorized.toLocaleString();
  document.getElementById('stat-uncategorized').textContent = uncategorizedRows.length.toLocaleString();
  document.getElementById('count-uncategorized').textContent = uncategorizedRows.length.toLocaleString();

  const ucl = document.getElementById('uncategorized-list');
  ucl.innerHTML = uncategorizedRows.length === 0
    ? '<div class="empty-state">Every sub category found a parent ✓</div>'
    : uncategorizedRows.slice(0,200).map(u => `<div class="result-pill unmatched"><span class="rp-sku">${u.sku}</span><span class="rp-name">${u.name||''}</span><span class="rp-miss">${u.subCategory}</span></div>`).join('')
      + (uncategorizedRows.length > 200 ? `<div class="empty-state">…and ${uncategorizedRows.length-200} more</div>` : '');

  document.getElementById('results-section').style.display = 'block';

  // Each location's download button only appears once that location's import
  // has actually been completed — no point offering an export with no stock data.
  document.getElementById('btn-download-pama').style.display = LOCATIONS.pama.done ? 'inline-flex' : 'none';
  document.getElementById('btn-download-point').style.display = LOCATIONS.point.done ? 'inline-flex' : 'none';
}

function searchSKU() {
  const q = document.getElementById('sku-search').value.trim();
  const container = document.getElementById('search-results');
  if (!q) { container.innerHTML = '<div class="empty-state">Type a SKU above to check its match</div>'; return; }
  const info = LOCATIONS[activeLocationView];
  const results = extractedRows.filter(r => r['SKU'].toLowerCase().includes(q.toLowerCase())).slice(0,20);
  if (!results.length) { container.innerHTML = '<div class="empty-state">No products found with that SKU</div>'; return; }
  container.innerHTML = results.map(r => {
    const stock = r[info.stockField];
    const isMatched = stock !== '' && stock !== NOT_MATCHED;
    const isZero = stock === '0';
    const weightTag = r['Weight'] === '21' ? `<span class="rp-weight">21kg</span>` : '';
    return `<div class="result-pill ${isMatched?(isZero?'zero':'matched'):'unmatched'}">
      <span class="rp-sku">${r['SKU']}</span>
      <span class="rp-name">${r['ITEM NAME']||''}</span>
      ${weightTag}
      ${isMatched?(isZero?`<span class="rp-zero">0</span>`:`<span class="rp-stock">${stock}</span>`):`<span class="rp-miss">Not in ${info.label.replace(' Shopping Mall','')}</span>`}
    </div>`;
  }).join('');
}

function showTab(tab) {
  ['search','unmatched','nostock','weighted','uncategorized'].forEach(t => {
    document.getElementById(`panel-${t}`).style.display = t===tab?'block':'none';
    document.getElementById(`tab-${t}`).className = 'inspector-tab'+(t===tab?' active':'');
  });
}

// Builds and downloads the export CSV for one location, swapping that
// location's stock field into the "Stock Count" column, sorted by that
// location's stock (highest first) — exactly as the single-location export
// always worked, just parameterized by which location is being exported.
// Fixes UTF-8 text that was misread as Latin-1/Windows-1252.
// Each corrupted sequence maps to exactly one correct character —
// this is a deterministic lookup, not a guess.
function fixEncoding(s) {
  if (!s) return s;
  return s
    // Multi-character sequences first (longest match wins)
    .replace(/â€™/g, '\u2019')   // ' right single quote / apostrophe
    .replace(/â€œ/g, '\u201C')   // " left double curly quote
    .replace(/â€/g,  '\u201D')   // " right double curly quote
    .replace(/â€"/g, '\u2013')   // – en dash
    .replace(/â€"/g, '\u2014')   // — em dash
    .replace(/â„¢/g, '\u2122')   // ™ trademark
    .replace(/Â®/g,  '\u00AE')   // ® registered trademark
    .replace(/Â°/g,  '\u00B0')   // ° degree sign
    .replace(/Â£/g,  '\u00A3')   // £ pound sign
    .replace(/Â©/g,  '\u00A9')   // © copyright
    .replace(/Ã©/g,  '\u00E9')   // é
    .replace(/Ã /g,  '\u00E0')   // à
    .replace(/Ã¨/g,  '\u00E8')   // è
    .replace(/Ã¹/g,  '\u00F9')   // ù
    .replace(/Ã¢/g,  '\u00E2')   // â
    .replace(/Ã®/g,  '\u00EE')   // î
    .replace(/Ã´/g,  '\u00F4')   // ô
    .replace(/Ã»/g,  '\u00FB')   // û
    .replace(/Ã«/g,  '\u00EB')   // ë
    .replace(/Ã¯/g,  '\u00EF')   // ï
    .replace(/Ã¼/g,  '\u00FC')   // ü
    .replace(/Ã¶/g,  '\u00F6')   // ö
    .replace(/Ã¤/g,  '\u00E4')   // ä
    .replace(/Ã±/g,  '\u00F1')   // ñ
    .replace(/Ã§/g,  '\u00E7')   // ç
    // Â followed by a space or at end = non-breaking space → regular space
    .replace(/Â /g, ' ')
    // Standalone Â (before a letter/number) = stray non-breaking space → remove
    .replace(/Â(?=[A-Za-z0-9])/g, '')
    // Any remaining lone Â = remove
    .replace(/Â/g, '')
    // Collapse any double-spaces left behind
    .replace(/ {2,}/g, ' ')
    .trim();
}

function downloadLocationCSV(loc) {
  const info = LOCATIONS[loc];
  const escape = v => `"${String(v).replace(/"/g,'""')}"`;
  const threshold = getThreshold();

  // Use mapped export header names (merchant_sku, name, etc.)
  const header = OUTPUT_FIELDS.map(f => escape(EXPORT_HEADERS[f] || f)).join(',');

  // Include ALL products from Magento for this location's export:
  // - Products found in the location file → sorted by stock (highest first)
  // - Products NOT found in the location file → appended at the bottom with stock 0, enabled FALSE
  let exportRows = sortByStock(extractedRows, info.stockField);

  // Split into matched (have stock data) and unmatched (no stock for this location)
  const matchedRows = exportRows.filter(row => {
    const stockVal = row[info.stockField];
    return stockVal !== '' && stockVal !== NOT_MATCHED && stockVal !== undefined && stockVal !== null;
  });
  const unmatchedRows = exportRows.filter(row => {
    const stockVal = row[info.stockField];
    return stockVal === '' || stockVal === NOT_MATCHED || stockVal === undefined || stockVal === null;
  });

  // Combine: matched first (sorted by stock), unmatched at the bottom
  exportRows = [...matchedRows, ...unmatchedRows];

  const rows = exportRows.map(row => OUTPUT_FIELDS.map(f => {
    const stockVal = row[info.stockField];
    const isUnmatched = stockVal === '' || stockVal === NOT_MATCHED || stockVal === undefined || stockVal === null;

    // enabled: FALSE for unmatched rows, or if stock < threshold, TRUE if stock >= threshold
    if (f === 'enabled') {
      if (isUnmatched) return escape('FALSE');
      const stockNum = parseFloat(stockVal);
      if (threshold === null || isNaN(stockNum)) return escape('FALSE');
      return escape(stockNum >= threshold ? 'TRUE' : 'FALSE');
    }

    // Stock Count: unmatched rows show as 0
    if (f === 'Stock Count') {
      return escape(isUnmatched ? '0' : (stockVal || '0'));
    }

    let val = row[f] || '';

    // Weight stored as '21' internally, exports as '21kg'
    if (f === 'Weight' && val === '21') val = '21kg';

    // Fix UTF-8 encoding corruption on text fields
    if (val && !['SKU','Weight','PRICE','enabled'].includes(f) && !f.startsWith('IMAGE URL')) {
      val = fixEncoding(val);
    }

    // SKU formatted as text formula so Excel doesn't mangle it
    if (f === 'SKU' && val) return `"=""${val}"""`;
    return escape(val);
  }).join(','));

  // UTF-8 BOM so Excel opens the file with correct encoding
  const blob = new Blob(['\uFEFF' + header+'\n'+rows.join('\n')], {type:'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${info.label} Wolt Stock.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function saveThreshold() {
  const val = document.getElementById('threshold-input').value;
  if (val === '' || val === null) {
    localStorage.removeItem('csv_extractor_threshold');
  } else {
    localStorage.setItem('csv_extractor_threshold', val);
  }
}

function getThreshold() {
  const val = document.getElementById('threshold-input') ? document.getElementById('threshold-input').value : '';
  if (val === '' || val === null) return null;
  const n = parseInt(val, 10);
  return isNaN(n) ? null : n;
}

function downloadWeightRulesCSV() {
  const escape = v => `"${String(v).replace(/"/g,'""')}"`;
  const rows = [];

  // Section: Single keywords
  rows.push([escape('RULE TYPE'), escape('KEYWORD A'), escape('KEYWORD B'), escape('EFFECT')].join(','));
  RULES.single.forEach(kw => {
    rows.push([escape('Single keyword'), escape(kw.replace(/\b\w/g,c=>c.toUpperCase())), escape(''), escape('Set weight to 21kg')].join(','));
  });

  // Section: Pair keywords (set)
  RULES.pairs.forEach(([a, b]) => {
    rows.push([escape('Pair (both must appear)'), escape(a.replace(/\b\w/g,c=>c.toUpperCase())), escape(b.replace(/\b\w/g,c=>c.toUpperCase())), escape('Set weight to 21kg')].join(','));
  });

  // Section: Single exclusions
  RULES.exclude.forEach(kw => {
    rows.push([escape('Single exclusion'), escape(kw.replace(/\b\w/g,c=>c.toUpperCase())), escape(''), escape('NEVER set 21kg if this word is present')].join(','));
  });

  // Section: Pair exclusions
  (RULES.excludePairs || []).forEach(([a, b]) => {
    rows.push([escape('Pair exclusion (both)'), escape(a.replace(/\b\w/g,c=>c.toUpperCase())), escape(b.replace(/\b\w/g,c=>c.toUpperCase())), escape('NEVER set 21kg if both appear together')].join(','));
  });

  // Section: Brand/export exclusions (hardcoded)
  BRAND_EXCLUSIONS.forEach(b => {
    rows.push([escape('Brand exclusion'), escape(b.toUpperCase()), escape(''), escape('Entire product row removed from export')].join(','));
  });
  rows.push([escape('Demo exclusion'), escape('Demo'), escape(''), escape('Entire product row removed from export')].join(','));
  rows.push([escape('Large TV exclusion'), escape('LG/Philips/Samsung/Metz + size ≥43"'), escape(''), escape('Entire product row removed from export')].join(','));
  rows.push([escape('Zero price exclusion'), escape('Price = 0 or blank'), escape(''), escape('Entire product row removed from export')].join(','));
  rows.push([escape('Sub Category exclusion'), escape('Sub Category contains SHOP'), escape(''), escape('Entire product row removed from export')].join(','));

  const blob = new Blob(['\uFEFF' + rows.join('\n')], {type:'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download='weight_rules.csv'; a.click();
  URL.revokeObjectURL(url);
}

function downloadNotInMagentoCSV() {
  const info = LOCATIONS[activeLocationView];
  const escape = v => `"${String(v).replace(/"/g,'""')}"`;
  const header = ['SKU','Stock Count','ITEM NAME'].map(escape).join(',');
  const rows = info.unmatched.map(p => {
    const skuCell = `"=""${p.sku}"""`;
    return [skuCell, escape(p.qty), escape(p.name || '')].join(',');
  });
  const blob = new Blob(['\uFEFF' + header+'\n'+rows.join('\n')],{type:'text/csv;charset=utf-8;'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `not_in_magento_${activeLocationView}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function resetStep1() {
  extractedRows=[]; weightedRows=[]; excludedRows=[]; uncategorizedRows=[]; step1Done=false; step2AnyDone=false;
  LOCATIONS.pama.stockMap={}; LOCATIONS.pama.unmatched=[]; LOCATIONS.pama.done=false; LOCATIONS.pama.fileName='';
  LOCATIONS.point.stockMap={}; LOCATIONS.point.unmatched=[]; LOCATIONS.point.done=false; LOCATIONS.point.fileName='';
  document.getElementById('results-section').style.display='none';
  document.getElementById('load1').style.display='none';
  document.getElementById('s1-dropwrap').innerHTML=`<div class="drop-zone" id="dz1" onclick="document.getElementById('fi1').click()"><div class="dz-cloud"><i class="ti ti-cloud-upload"></i></div><div class="dz-title">Upload your product file here</div><div class="dz-sub">Drag &amp; Drop<br>System &gt; Export &gt; Entity Type &gt; Products<br><span style="color:#9a9690;font-size:11px">This import includes: sku · name · price · description · additional_images</span></div><input type="file" id="fi1" accept=".csv,.tsv,.txt"></div>`;
  document.getElementById('s1-num').className='step-num';
  document.getElementById('s1-badge').textContent='Waiting'; document.getElementById('s1-badge').className='step-badge pending';
  initDZ1(); resetStep2(true);
}

function resetStep2(lock) {
  document.getElementById('results-section').style.display='none';
  document.getElementById('location-note').style.display='none';
  document.getElementById('s2-num').className=lock?'step-num locked':'step-num';
  document.getElementById('s2-title').className=lock?'step-title locked':'step-title';
  document.getElementById('s2-badge').textContent=lock?'Locked':'Ready';
  document.getElementById('s2-badge').className='step-badge pending';
  step2AnyDone = false;
  document.getElementById('load-pama').style.display='none';
  document.getElementById('load-point').style.display='none';
  if (lock) {
    document.getElementById('pama-dropwrap').innerHTML=`<div class="drop-zone locked-zone" id="dz-pama"><div class="dz-cloud"><i class="ti ti-lock"></i></div><div class="dz-title">Complete Step 1 first</div><div class="dz-sub">Upload Inventory Valuation</div></div>`;
    document.getElementById('point-dropwrap').innerHTML=`<div class="drop-zone locked-zone" id="dz-point"><div class="dz-cloud"><i class="ti ti-lock"></i></div><div class="dz-title">Complete Step 1 first</div><div class="dz-sub">Upload Inventory Valuation</div></div>`;
    resetStep3(true);
  } else {
    extractedRows.forEach(r => { r[STOCK_FIELD_PAMA] = NOT_MATCHED; r[STOCK_FIELD_POINT] = NOT_MATCHED; });
    unlockStep2();
    resetStep3(true);
  }
}

function resetAll() { resetStep1(); }
