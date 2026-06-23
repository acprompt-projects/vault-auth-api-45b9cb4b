const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../../src/app');
const { db, resetDb } = require('../../src/db');

const JWT_SECRET = process.env.JWT_SECRET || 'test-secret-key';

let adminToken, userToken, userId, vaultId;

beforeAll(async () => {
  await resetDb();
  // Seed admin
  const adminRes = await request(app)
    .post('/api/auth/register')
    .send({ email: 'admin@vault.io', password: 'Admin123!', name: 'Admin', role: 'admin' });
  adminToken = adminRes.body.token;
  // Seed regular user
  const userRes = await request(app)
    .post('/api/auth/register')
    .send({ email: 'user@vault.io', password: 'User123!', name: 'User', role: 'user' });
  userToken = userRes.body.token;
  userId = userRes.body.user.id;
});

afterAll(async () => {
  await db.close();
});

describe('Auth Flow', () => {
  test('POST /api/auth/register — creates user and returns token', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'new@vault.io', password: 'New123!', name: 'NewUser', role: 'user' });
    expect(res.status).toBe(201);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.email).toBe('new@vault.io');
    const decoded = jwt.verify(res.body.token, JWT_SECRET);
    expect(decoded.role).toBe('user');
  });

  test('POST /api/auth/register — rejects duplicate email', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'user@vault.io', password: 'Xyz123!', name: 'Dup', role: 'user' });
    expect(res.status).toBe(409);
  });

  test('POST /api/auth/register — validates input', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'bad', password: '1', name: '' });
    expect(res.status).toBe(400);
    expect(res.body.errors).toBeDefined();
  });

  test('POST /api/auth/login — returns token for valid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'user@vault.io', password: 'User123!' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.email).toBe('user@vault.io');
  });

  test('POST /api/auth/login — rejects wrong password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'user@vault.io', password: 'Wrong123!' });
    expect(res.status).toBe(401);
  });

  test('POST /api/auth/login — rejects unknown email', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'ghost@vault.io', password: 'Ghost123!' });
    expect(res.status).toBe(401);
  });

  test('GET /api/auth/me — returns current user with valid token', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(200);
    expect(res.body.email).toBe('user@vault.io');
  });

  test('GET /api/auth/me — rejects missing token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });
});

describe('User CRUD (Admin)', () => {
  test('GET /api/users — admin lists all users', async () => {
    const res = await request(app)
      .get('/api/users')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThanOrEqual(2);
  });

  test('GET /api/users — non-admin forbidden', async () => {
    const res = await request(app)
      .get('/api/users')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(403);
  });

  test('GET /api/users/:id — admin gets single user', async () => {
    const res = await request(app)
      .get(`/api/users/${userId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(userId);
  });

  test('PUT /api/users/:id — admin updates user', async () => {
    const res = await request(app)
      .put(`/api/users/${userId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'Updated User' });
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Updated User');
  });

  test('DELETE /api/users/:id — admin deletes non-admin user', async () => {
    const regRes = await request(app)
      .post('/api/auth/register')
      .send({ email: 'todelete@vault.io', password: 'Del123!', name: 'ToDelete', role: 'user' });
    const delId = regRes.body.user.id;
    const res = await request(app)
      .delete(`/api/users/${delId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(204);
  });

  test('DELETE /api/users/:id — non-admin forbidden', async () => {
    const res = await request(app)
      .delete(`/api/users/${userId}`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(403);
  });
});

describe('Vault CRUD', () => {
  const entry = { title: 'API Key', category: 'credential', data: { key: 'sk-abc123', env: 'prod' } };

  test('POST /api/vault — user creates vault entry', async () => {
    const res = await request(app)
      .post('/api/vault')
      .set('Authorization', `Bearer ${userToken}`)
      .send(entry);
    expect(res.status).toBe(201);
    expect(res.body.id).toBeDefined();
    expect(res.body.title).toBe('API Key');
    vaultId = res.body.id;
  });

  test('GET /api/vault — user lists own entries', async () => {
    const res = await request(app)
      .get('/api/vault')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThanOrEqual(1);
  });

  test('GET /api/vault/:id — user retrieves own entry', async () => {
    const res = await request(app)
      .get(`/api/vault/${vaultId}`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(vaultId);
    expect(res.body.data.key).toBe('sk-abc123');
  });

  test('PUT /api/vault/:id — user updates own entry', async () => {
    const res = await request(app)
      .put(`/api/vault/${vaultId}`)
      .set('Authorization', `Bearer ${userToken}`)
      .send({ title: 'Prod API Key', data: { key: 'sk-updated', env: 'prod' } });
    expect(res.status).toBe(200);
    expect(res.body.title).toBe('Prod API Key');
    expect(res.body.data.key).toBe('sk-updated');
  });

  test('GET /api/vault/:id — other user cannot access', async () => {
    const res = await request(app)
      .get(`/api/vault/${vaultId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200); // admin can access all
  });

  test('DELETE /api/vault/:id — user deletes own entry', async () => {
    const res = await request(app)
      .delete(`/api/vault/${vaultId}`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(204);
  });

  test('GET /api/vault/:id — returns 404 for deleted entry', async () => {
    const res = await request(app)
      .get(`/api/vault/${vaultId}`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(404);
  });

  test('POST /api/vault — rejects unauthenticated', async () => {
    const res = await request(app).post('/api/vault').send(entry);
    expect(res.status).toBe(401);
  });

  test('POST /api/vault — validates required fields', async () => {
    const res = await request(app)
      .post('/api/vault')
      .set('Authorization', `Bearer ${userToken}`)
      .send({ category: 'credential' });
    expect(res.status).toBe(400);
  });
});

describe('OpenAPI Spec Validation', () => {
  test('GET /api/docs — returns OpenAPI JSON spec', async () => {
    const res = await request(app).get('/api/docs');
    expect(res.status).toBe(200);
    expect(res.body.openapi).toMatch(/^3\./);
    expect(res.body.info.title).toBeDefined();
    const paths = Object.keys(res.body.paths);
    expect(paths).toContain('/api/auth/register');
    expect(paths).toContain('/api/auth/login');
    expect(paths).toContain('/api/auth/me');
    expect(paths).toContain('/api/users');
    expect(paths).toContain('/api/vault');
  });

  test('OpenAPI spec has security schemes defined', async () => {
    const res = await request(app).get('/api/docs');
    const schemes = res.body.components.securitySchemes;
    expect(schemes).toBeDefined();
    expect(schemes.bearerAuth).toBeDefined();
    expect(schemes.bearerAuth.type).toBe('http');
    expect(schemes.bearerAuth.scheme).toBe('bearer');
  });
});