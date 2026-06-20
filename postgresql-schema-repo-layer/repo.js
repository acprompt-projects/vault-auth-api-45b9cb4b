const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: parseInt(process.env.DB_POOL_MAX || "20", 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on("error", (err) => {
  console.error("Unexpected pg pool error:", err.message);
});

const query = (text, params) => pool.query(text, params);
const getClient = () => pool.connect();

/* ---------- Role Repo ---------- */
const RoleRepo = {
  create(name, description, permissions = []) {
    return query(
      "INSERT INTO roles (name, description, permissions) VALUES ($1,$2,$3) RETURNING *",
      [name, description, JSON.stringify(permissions)]
    );
  },
  findById(id) {
    return query("SELECT * FROM roles WHERE id = $1", [id]);
  },
  findByName(name) {
    return query("SELECT * FROM roles WHERE name = $1", [name]);
  },
  findAll(limit = 50, offset = 0) {
    return query("SELECT * FROM roles ORDER BY created_at DESC LIMIT $1 OFFSET $2", [limit, offset]);
  },
  update(id, fields) {
    const sets = [];
    const vals = [id];
    let n = 2;
    for (const [k, v] of Object.entries(fields)) {
      sets.push(`${k} = $${n++}`);
      vals.push(k === "permissions" ? JSON.stringify(v) : v);
    }
    if (!sets.length) return Promise.resolve({ rows: [] });
    return query(`UPDATE roles SET ${sets.join(", ")} WHERE id = $1 RETURNING *`, vals);
  },
  remove(id) {
    return query("DELETE FROM roles WHERE id = $1 RETURNING id", [id]);
  },
};

/* ---------- User Repo ---------- */
const UserRepo = {
  create(email, passwordHash, roleId, isActive = true) {
    return query(
      "INSERT INTO users (email, password_hash, role_id, is_active) VALUES ($1,$2,$3,$4) RETURNING id, email, role_id, is_active, created_at",
      [email, passwordHash, roleId, isActive]
    );
  },
  findById(id) {
    return query(
      "SELECT u.id, u.email, u.role_id, u.is_active, u.created_at, u.updated_at, r.name AS role_name, r.permissions " +
      "FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1",
      [id]
    );
  },
  findByEmail(email) {
    return query(
      "SELECT u.*, r.name AS role_name, r.permissions FROM users u JOIN roles r ON r.id = u.role_id WHERE u.email = $1",
      [email]
    );
  },
  findAll(limit = 50, offset = 0) {
    return query(
      "SELECT u.id, u.email, u.role_id, u.is_active, u.created_at, r.name AS role_name " +
      "FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.created_at DESC LIMIT $1 OFFSET $2",
      [limit, offset]
    );
  },
  update(id, fields) {
    const sets = [];
    const vals = [id];
    let n = 2;
    for (const [k, v] of Object.entries(fields)) {
      sets.push(`${k} = $${n++}`);
      vals.push(v);
    }
    if (!sets.length) return Promise.resolve({ rows: [] });
    return query(`UPDATE users SET ${sets.join(", ")} WHERE id = $1 RETURNING id, email, role_id, is_active`, vals);
  },
  remove(id) {
    return query("DELETE FROM users WHERE id = $1 RETURNING id", [id]);
  },
};

/* ---------- Secret Repo ---------- */
const SecretRepo = {
  create(userId, key, encryptedValue) {
    return query(
      "INSERT INTO secrets (user_id, key, encrypted_value) VALUES ($1,$2,$3) RETURNING id, user_id, key, created_at",
      [userId, key, encryptedValue]
    );
  },
  findById(id) {
    return query("SELECT * FROM secrets WHERE id = $1", [id]);
  },
  findByUserIdAndKey(userId, key) {
    return query("SELECT * FROM secrets WHERE user_id = $1 AND key = $2", [userId, key]);
  },
  findByUserId(userId, limit = 50, offset = 0) {
    return query("SELECT id, user_id, key, created_at, updated_at FROM secrets WHERE user_id = $1 ORDER BY key LIMIT $2 OFFSET $3", [userId, limit, offset]);
  },
  update(id, encryptedValue) {
    return query("UPDATE secrets SET encrypted_value = $1 WHERE id = $2 RETURNING id, user_id, key, updated_at", [encryptedValue, id]);
  },
  remove(id) {
    return query("DELETE FROM secrets WHERE id = $1 RETURNING id", [id]);
  },
};

/* ---------- Audit Log Repo ---------- */
const AuditLogRepo = {
  create({ userId, action, resourceType, resourceId, details = {}, ipAddress }) {
    return query(
      "INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
      [userId, action, resourceType, resourceId, JSON.stringify(details), ipAddress || null]
    );
  },
  findByUserId(userId, limit = 50, offset = 0) {
    return query("SELECT * FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", [userId, limit, offset]);
  },
  findAll(limit = 50, offset = 0) {
    return query("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2", [limit, offset]);
  },
};

module.exports = { pool, query, getClient, RoleRepo, UserRepo, SecretRepo, AuditLogRepo };