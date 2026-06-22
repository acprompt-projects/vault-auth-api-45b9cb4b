const express = require('express');
const { encrypt, decrypt, generateSalt } = require('./crypto');

const router = express.Router();

// --- In-memory stores (swap with DB in production) ---
const secrets = new Map();   // id -> { userId, name, enc, salt, policy, createdAt, updatedAt }
const access  = new Map();   // id -> [{ userId, role }]  role: owner|admin|write|read

let idCounter = 1;
const MASTER = process.env.VAULT_MASTER_SECRET || 'change-me-in-prod-32ch!!';

// --- Auth middleware (expects req.user set by upstream JWT middleware) ---
function requireAuth(req, res, next) {
  if (!req.user || !req.user.id) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function resolveSecret(id) {
  const sid = String(id);
  if (!secrets.has(sid)) return null;
  const sec = secrets.get(sid);
  const acl = access.get(sid) || [];
  return { sec, acl };
}

function userRole(acl, userId) {
  const entry = acl.find(e => e.userId === userId);
  return entry ? entry.role : null;
}

function canRead(role)  { return role === 'owner' || role === 'admin' || role === 'write' || role === 'read'; }
function canWrite(role) { return role === 'owner' || role === 'admin' || role === 'write'; }
function canAdmin(role) { return role === 'owner' || role === 'admin'; }
function isOwner(role)  { return role === 'owner'; }

// CREATE
router.post('/', requireAuth, (req, res) => {
  const { name, value, policy = 'private', grantAccess = [] } = req.body;
  if (!name || value === undefined) return res.status(400).json({ error: 'name and value required' });
  const id = String(idCounter++);
  const salt = generateSalt();
  const enc = encrypt(String(value), MASTER, salt);
  const now = new Date().toISOString();
  secrets.set(id, { userId: req.user.id, name, enc, salt: salt.toString('base64'), policy, createdAt: now, updatedAt: now });
  const acl = [{ userId: req.user.id, role: 'owner' }];
  for (const g of grantAccess) {
    if (g.userId && g.role && ['admin','write','read'].includes(g.role) && g.userId !== req.user.id) {
      acl.push({ userId: g.userId, role: g.role });
    }
  }
  access.set(id, acl);
  res.status(201).json({ id, name, policy, createdAt: now });
});

// LIST (titles only)
router.get('/', requireAuth, (req, res) => {
  const results = [];
  for (const [id, sec] of secrets) {
    const acl = access.get(id) || [];
    if (canRead(userRole(acl, req.user.id))) {
      results.push({ id, name: sec.name, policy: sec.policy, createdAt: sec.createdAt, updatedAt: sec.updatedAt });
    }
  }
  res.json(results);
});

// READ (decrypt)
router.get('/:id', requireAuth, (req, res) => {
  const found = resolveSecret(req.params.id);
  if (!found) return res.status(404).json({ error: 'Secret not found' });
  const role = userRole(found.acl, req.user.id);
  if (!canRead(role)) return res.status(403).json({ error: 'Access denied' });
  try {
    const salt = Buffer.from(found.sec.salt, 'base64');
    const value = decrypt(found.sec.enc, MASTER, salt);
    res.json({ id: req.params.id, name: found.sec.name, value, policy: found.sec.policy, updatedAt: found.sec.updatedAt });
  } catch (e) {
    res.status(500).json({ error: 'Decryption failed' });
  }
});

// UPDATE
router.put('/:id', requireAuth, (req, res) => {
  const found = resolveSecret(req.params.id);
  if (!found) return res.status(404).json({ error: 'Secret not found' });
  const role = userRole(found.acl, req.user.id);
  if (!canWrite(role)) return res.status(403).json({ error: 'Access denied' });
  const { name, value, policy } = req.body;
  if (name) found.sec.name = name;
  if (policy && isOwner(role)) found.sec.policy = policy;
  if (value !== undefined) {
    const salt = Buffer.from(found.sec.salt, 'base64');
    found.sec.enc = encrypt(String(value), MASTER, salt);
  }
  found.sec.updatedAt = new Date().toISOString();
  res.json({ id: req.params.id, name: found.sec.name, policy: found.sec.policy, updatedAt: found.sec.updatedAt });
});

// UPDATE ACCESS (grant/revoke)
router.patch('/:id/access', requireAuth, (req, res) => {
  const found = resolveSecret(req.params.id);
  if (!found) return res.status(404).json({ error: 'Secret not found' });
  const role = userRole(found.acl, req.user.id);
  if (!canAdmin(role)) return res.status(403).json({ error: 'Admin access required' });
  const { grant = [], revoke = [] } = req.body;
  for (const g of grant) {
    if (g.userId && g.role && ['admin','write','read'].includes(g.role) && g.userId !== found.sec.userId) {
      const idx = found.acl.findIndex(a => a.userId === g.userId);
      if (idx >= 0) found.acl[idx].role = g.role; else found.acl.push({ userId: g.userId, role: g.role });
    }
  }
  for (const uid of revoke) {
    if (uid !== found.sec.userId) {
      const idx = found.acl.findIndex(a => a.userId === uid);
      if (idx >= 0) found.acl.splice(idx, 1);
    }
  }
  res.json({ id: req.params.id, access: found.acl });
});

// DELETE
router.delete('/:id', requireAuth, (req, res) => {
  const found = resolveSecret(req.params.id);
  if (!found) return res.status(404).json({ error: 'Secret not found' });
  const role = userRole(found.acl, req.user.id);
  if (!isOwner(role)) return res.status(403).json({ error: 'Owner access required' });
  secrets.delete(req.params.id);
  access.delete(req.params.id);
  res.json({ deleted: true, id: req.params.id });
});

module.exports = router;