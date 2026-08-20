const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const request = require('supertest');

let mongod;
let app;

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongod.getUri();
  process.env.JWT_SECRET = 'test-secret';
  process.env.NODE_ENV = 'test';
  delete process.env.CLOUDINARY_URL; // keep photo uploads disabled in tests
  delete process.env.TWILIO_SID;

  // server.js connects to Mongo and starts listening only when run directly;
  // requiring it here just builds the app and kicks off the connection.
  app = require('../server');

  // Wait for the connection to be ready before running requests against it.
  await new Promise((resolve, reject) => {
    if (mongoose.connection.readyState === 1) return resolve();
    mongoose.connection.once('open', resolve);
    mongoose.connection.once('error', reject);
  });
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongod.stop();
});

async function createAdmin() {
  // Bootstrap the first admin directly via the DB, since /api/auth/register is admin-only.
  const bcrypt = require('bcryptjs');
  const User = mongoose.model('User');
  const hashed = await bcrypt.hash('adminpass', 10);
  await User.create({ email: 'admin@test.com', password: hashed, name: 'Admin', role: 'admin' });
  const res = await request(app).post('/api/auth/login').send({ email: 'admin@test.com', password: 'adminpass' });
  return res.body.token;
}

describe('auth', () => {
  test('rejects requests to protected routes with no token', async () => {
    const res = await request(app).get('/api/properties');
    expect(res.status).toBe(401);
  });

  test('rejects login with missing fields', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'x@x.com' });
    expect(res.status).toBe(400);
  });

  test('rejects login with wrong password', async () => {
    await createAdmin();
    const res = await request(app).post('/api/auth/login').send({ email: 'admin@test.com', password: 'wrong' });
    expect(res.status).toBe(401);
  });

  test('logs in successfully and returns a token', async () => {
    const bcrypt = require('bcryptjs');
    const User = mongoose.model('User');
    await User.deleteMany({});
    const hashed = await bcrypt.hash('pass123', 10);
    await User.create({ email: 'user@test.com', password: hashed, name: 'User', role: 'crew' });
    const res = await request(app).post('/api/auth/login').send({ email: 'user@test.com', password: 'pass123' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
  });
});

describe('registration is admin-only', () => {
  test('rejects unauthenticated registration', async () => {
    const res = await request(app).post('/api/auth/register').send({ email: 'a@b.com', password: 'password1', name: 'A' });
    expect(res.status).toBe(401);
  });

  test('rejects registration by a non-admin', async () => {
    const bcrypt = require('bcryptjs');
    const User = mongoose.model('User');
    await User.deleteMany({});
    const hashed = await bcrypt.hash('pass123', 10);
    await User.create({ email: 'crew@test.com', password: hashed, name: 'Crew', role: 'crew' });
    const login = await request(app).post('/api/auth/login').send({ email: 'crew@test.com', password: 'pass123' });
    const res = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${login.body.token}`)
      .send({ email: 'new@test.com', password: 'password1', name: 'New' });
    expect(res.status).toBe(403);
  });

  test('allows registration by an admin', async () => {
    const mongoose2 = require('mongoose');
    await mongoose2.model('User').deleteMany({});
    const token = await createAdmin();
    const res = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${token}`)
      .send({ email: 'crew2@test.com', password: 'password1', name: 'Crew Two', role: 'crew' });
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('crew2@test.com');
  });

  test('rejects a weak password', async () => {
    const token = await (async () => {
      const login = await request(app).post('/api/auth/login').send({ email: 'admin@test.com', password: 'adminpass' });
      return login.body.token;
    })();
    const res = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${token}`)
      .send({ email: 'weak@test.com', password: '123', name: 'Weak' });
    expect(res.status).toBe(400);
  });
});

describe('property permissions', () => {
  let adminToken, crewToken, propertyId;

  beforeAll(async () => {
    const mongoose2 = require('mongoose');
    await mongoose2.model('User').deleteMany({});
    await mongoose2.model('Property').deleteMany({});
    adminToken = await createAdmin();

    await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: 'crew3@test.com', password: 'password1', name: 'Crew Three', role: 'crew' });
    const login = await request(app).post('/api/auth/login').send({ email: 'crew3@test.com', password: 'password1' });
    crewToken = login.body.token;

    const created = await request(app)
      .post('/api/properties')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ address: '1 Main St', city: 'Testville', size: 1000 });
    propertyId = created.body._id;
  });

  test('a logged-in crew member can create and list properties', async () => {
    const res = await request(app).get('/api/properties').set('Authorization', `Bearer ${crewToken}`);
    expect(res.status).toBe(200);
    expect(res.body.properties.length).toBeGreaterThan(0);
  });

  test('crew cannot delete a property', async () => {
    const res = await request(app).delete(`/api/properties/${propertyId}`).set('Authorization', `Bearer ${crewToken}`);
    expect(res.status).toBe(403);
  });

  test('crew cannot update a property (manager/admin only)', async () => {
    const res = await request(app)
      .put(`/api/properties/${propertyId}`)
      .set('Authorization', `Bearer ${crewToken}`)
      .send({ size: 2000 });
    expect(res.status).toBe(403);
  });

  test('admin can delete a property', async () => {
    const res = await request(app).delete(`/api/properties/${propertyId}`).set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });

  test('rejects a property missing required fields', async () => {
    const res = await request(app)
      .post('/api/properties')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ size: 500 });
    expect(res.status).toBe(400);
  });
});

describe('team directory is available to any authenticated user', () => {
  test('a crew member can list team members for crew-assignment purposes', async () => {
    const mongoose2 = require('mongoose');
    await mongoose2.model('User').deleteMany({});
    const bcrypt = require('bcryptjs');
    const User = mongoose2.model('User');
    const hashed = await bcrypt.hash('pass123', 10);
    await User.create({ email: 'teamcrew@test.com', password: hashed, name: 'Team Crew', role: 'crew' });
    const login = await request(app).post('/api/auth/login').send({ email: 'teamcrew@test.com', password: 'pass123' });
    const res = await request(app).get('/api/team').set('Authorization', `Bearer ${login.body.token}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body[0].email).toBe('teamcrew@test.com');
  });

  test('rejects unauthenticated team directory requests', async () => {
    const res = await request(app).get('/api/team');
    expect(res.status).toBe(401);
  });
});

describe('users management is admin-only', () => {
  test('non-admin cannot list users', async () => {
    const mongoose2 = require('mongoose');
    await mongoose2.model('User').deleteMany({});
    const bcrypt = require('bcryptjs');
    const User = mongoose2.model('User');
    const hashed = await bcrypt.hash('pass123', 10);
    await User.create({ email: 'plain@test.com', password: hashed, name: 'Plain', role: 'crew' });
    const login = await request(app).post('/api/auth/login').send({ email: 'plain@test.com', password: 'pass123' });
    const res = await request(app).get('/api/users').set('Authorization', `Bearer ${login.body.token}`);
    expect(res.status).toBe(403);
  });

  test('admin cannot delete their own account', async () => {
    const token = await createAdmin();
    const decoded = require('jsonwebtoken').decode(token);
    const res = await request(app).delete(`/api/users/${decoded.id}`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
  });
});
