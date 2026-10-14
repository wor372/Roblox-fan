const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CONFIG_FILE = path.join(DATA_DIR, 'guild-config.json');
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(CONFIG_FILE)) fs.writeFileSync(CONFIG_FILE, '{}');

app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: 'sharpbot.sid',
  secret: process.env.SESSION_SECRET || 'replace-this-session-secret-before-deploying',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

const defaultConfig = () => ({
  general: { language: 'cs', timezone: 'Europe/Prague', color: '#7c3aed', prefix: '/', logChannel: '' },
  tickets: { enabled: true, category: '', supportRole: '', transcriptChannel: '', claimButton: true, notifyMember: true },
  roles: { botManagerRole: '', ateamRole: '', supportRole: '', moderatorRole: '', adminRole: '', managementRole: '' },
  moderation: { enabled: true, warn: true, timeout: true, kick: true, ban: true, logChannel: '' },
  protection: { antiSpam: true, antiFlood: true, antiRaid: true, antiLinks: false, maxMentions: 5, raidThreshold: 8 },
  verification: { enabled: true, channel: '', verifiedRole: '', method: 'button' },
  giveaways: { enabled: true, announceChannel: '', defaultDuration: '1h' },
  logs: { enabled: true, messageLogs: true, memberLogs: true, moderationLogs: true, channel: '' },
  welcome: { enabled: true, channel: '', message: 'Vítej na serveru, {user}!' }
});
function readConfigs() { try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch { return {}; } }
function writeConfigs(data) { fs.writeFileSync(CONFIG_FILE, JSON.stringify(data, null, 2)); }
function redirectUri() { return process.env.DISCORD_REDIRECT_URI; }
function ensureOAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Přihlas se přes Discord.' });
  next();
}
function allowedUser(req) {
  const raw = process.env.ALLOWED_USER_IDS;
  return !raw || raw.split(',').map(s => s.trim()).filter(Boolean).includes(req.session.user.id);
}
function requireAllowed(req, res, next) {
  if (!allowedUser(req)) return res.status(403).json({ error: 'Tento účet nemá povolený přístup k dashboardu.' });
  next();
}
function botManagerOnly(req, res, next) {
  if (!req.session.selectedGuild) return res.status(400).json({ error: 'Nejdřív vyber server.' });
  const guild = (req.session.guilds || []).find(g => g.id === req.session.selectedGuild);
  if (!guild) return res.status(403).json({ error: 'Server není dostupný.' });
  // Discord OAuth guilds endpoint only reports the user's own permissions.
  // Manage Guild / Administrator is required here; in-bot Bot Manager checks should also be enforced.
  const perms = BigInt(guild.permissions || '0');
  const MANAGE_GUILD = 1n << 5n;
  const ADMINISTRATOR = 1n << 3n;
  if ((perms & MANAGE_GUILD) === 0n && (perms & ADMINISTRATOR) === 0n) {
    return res.status(403).json({ error: 'Pro správu tohoto serveru potřebuješ oprávnění Spravovat server nebo Administrátor.' });
  }
  next();
}

app.get('/health', (_req, res) => res.json({ ok: true, app: 'Sharp Bot Dashboard' }));
app.get('/auth/login', (req, res) => {
  if (!process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_CLIENT_SECRET || !redirectUri()) {
    return res.status(500).send('Chybí DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET nebo DISCORD_REDIRECT_URI v proměnných prostředí.');
  }
  const state = crypto.randomBytes(24).toString('hex');
  req.session.oauthState = state;
  const params = new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, redirect_uri: redirectUri(), response_type: 'code', scope: 'identify guilds', state });
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});
app.get('/auth/callback', async (req, res) => {
  try {
    if (!req.query.code || !req.query.state || req.query.state !== req.session.oauthState) return res.status(400).send('Přihlášení se nepodařilo ověřit. Vrať se a zkus to znovu.');
    delete req.session.oauthState;
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID, client_secret: process.env.DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code: req.query.code, redirect_uri: redirectUri() })
    });
    const token = await tokenResponse.json();
    if (!tokenResponse.ok || !token.access_token) return res.status(401).send('Discord přihlášení selhalo. Zkontroluj Client ID, Client Secret a Redirect URI.');
    const headers = { Authorization: `Bearer ${token.access_token}` };
    const [userResponse, guildResponse] = await Promise.all([
      fetch('https://discord.com/api/users/@me', { headers }),
      fetch('https://discord.com/api/users/@me/guilds', { headers })
    ]);
    if (!userResponse.ok || !guildResponse.ok) return res.status(401).send('Nepodařilo se načíst Discord účet nebo servery.');
    req.session.user = await userResponse.json();
    req.session.guilds = await guildResponse.json();
    req.session.selectedGuild = null;
    res.redirect('/');
  } catch (e) { console.error(e); res.status(500).send('Chyba při přihlašování přes Discord.'); }
});
app.post('/auth/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', (req, res) => res.json({ user: req.session.user || null, allowed: !!req.session.user && allowedUser(req), selectedGuild: req.session.selectedGuild || null }));
app.get('/api/guilds', ensureOAuth, requireAllowed, (req, res) => {
  const guilds = (req.session.guilds || []).filter(g => {
    const p = BigInt(g.permissions || '0'); return (p & (1n << 5n)) !== 0n || (p & (1n << 3n)) !== 0n;
  }).map(g => ({ id: g.id, name: g.name, icon: g.icon, permissions: g.permissions }));
  res.json({ guilds });
});
app.post('/api/select-guild', ensureOAuth, requireAllowed, (req, res) => {
  const id = String(req.body.guildId || '');
  const guild = (req.session.guilds || []).find(g => g.id === id);
  if (!guild) return res.status(403).json({ error: 'Tento server nemáš dostupný s oprávněním Spravovat server.' });
  req.session.selectedGuild = id;
  res.json({ ok: true, guild: { id: guild.id, name: guild.name } });
});
app.get('/api/config', ensureOAuth, requireAllowed, botManagerOnly, (req, res) => {
  const all = readConfigs();
  res.json({ config: { ...defaultConfig(), ...(all[req.session.selectedGuild] || {}) }, guildId: req.session.selectedGuild });
});
app.put('/api/config/:category', ensureOAuth, requireAllowed, botManagerOnly, (req, res) => {
  const category = req.params.category;
  const defaults = defaultConfig();
  if (!Object.prototype.hasOwnProperty.call(defaults, category)) return res.status(404).json({ error: 'Neznámá kategorie nastavení.' });
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) return res.status(400).json({ error: 'Neplatná data.' });
  const allowedKeys = new Set(Object.keys(defaults[category]));
  const safe = {};
  for (const [key, value] of Object.entries(req.body)) {
    if (!allowedKeys.has(key)) continue;
    if (typeof value === 'string') safe[key] = value.slice(0, 2000);
    else if (typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) safe[key] = value;
  }
  const all = readConfigs();
  all[req.session.selectedGuild] ||= {};
  all[req.session.selectedGuild][category] = { ...(all[req.session.selectedGuild][category] || defaults[category]), ...safe };
  writeConfigs(all);
  res.json({ ok: true, config: all[req.session.selectedGuild][category], note: 'Uloženo na webovém serveru. Pro synchronizaci s botem je potřeba propojit API s botem.' });
});
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`Sharp Bot Dashboard běží na portu ${PORT}`));
