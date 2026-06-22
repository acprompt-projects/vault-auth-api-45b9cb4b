const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'vault-auth-api-secret-change-in-prod';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '1h';

/**
 * Verify JWT token from Authorization header.
 * Attaches decoded payload to req.user on success.
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Access denied', message: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      const message = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
      return res.status(401).json({ error: 'Unauthorized', message });
    }
    req.user = decoded;
    next();
  });
}

/**
 * Optionally extract user if token present, but don't reject if absent.
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (!err) req.user = decoded;
      next();
    });
  } else {
    next();
  }
}

/**
 * Generate a signed JWT for a given payload.
 */
function signToken(payload, opts = {}) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: opts.expiresIn || JWT_EXPIRY });
}

/**
 * Decode token without verifying (for inspection only).
 */
function decodeToken(token) {
  return jwt.decode(token, { complete: true });
}

module.exports = { authenticateToken, optionalAuth, signToken, decodeToken, JWT_SECRET };