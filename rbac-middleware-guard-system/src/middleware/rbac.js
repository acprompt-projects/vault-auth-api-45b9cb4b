const { authenticateToken } = require('./auth');

const VALID_ROLES = ['admin', 'user', 'service'];

const ROLE_PERMISSIONS = {
  admin:   ['vault:read', 'vault:write', 'vault:delete', 'vault:manage', 'user:read', 'user:write', 'user:delete', 'system:admin'],
  user:    ['vault:read', 'vault:write'],
  service: ['vault:read', 'vault:write', 'vault:delete', 'system:service'],
};

/**
 * Ensure req.user has one of the allowed roles.
 * Must be used AFTER authenticateToken.
 */
function requireRole(...allowedRoles) {
  const normalized = allowedRoles.map(r => r.toLowerCase());
  const invalid = normalized.filter(r => !VALID_ROLES.includes(r));
  if (invalid.length) throw new Error(`Invalid role(s): ${invalid.join(', ')}`);

  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
    if (!normalized.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden', message: `Requires role: ${normalized.join('|')}` });
    }
    next();
  };
}

/**
 * Ensure req.user has ALL specified permissions.
 * Must be used AFTER authenticateToken.
 */
function requirePermissions(...requiredPermissions) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
    const userPerms = ROLE_PERMISSIONS[req.user.role] || [];
    const missing = requiredPermissions.filter(p => !userPerms.includes(p));
    if (missing.length) {
      return res.status(403).json({ error: 'Forbidden', message: `Missing permissions: ${missing.join(', ')}` });
    }
    next();
  };
}

/**
 * Ensure req.user has ANY of the specified permissions.
 * Must be used AFTER authenticateToken.
 */
function requireAnyPermission(...permissions) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
    const userPerms = ROLE_PERMISSIONS[req.user.role] || [];
    const hasAny = permissions.some(p => userPerms.includes(p));
    if (!hasAny) {
      return res.status(403).json({ error: 'Forbidden', message: `Requires one of: ${permissions.join(', ')}` });
    }
    next();
  };
}

/**
 * Ensure the authenticated user can only access their own resource,
 * unless they hold the admin role.
 * Parameter name in route is configurable (default: 'id').
 */
function requireOwnership(paramName = 'id') {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
    if (req.user.role === 'admin') return next();
    const targetId = req.params[paramName];
    if (String(req.user.sub) !== String(targetId)) {
      return res.status(403).json({ error: 'Forbidden', message: 'You can only access your own resources' });
    }
    next();
  };
}

/**
 * Combine authenticateToken + role check into a single middleware.
 */
function guard(roles) {
  const roleMiddleware = requireRole(...roles);
  return [authenticateToken, roleMiddleware];
}

/**
 * Combine authenticateToken + permission check into a single middleware.
 */
function guardWithPermissions(...perms) {
  return [authenticateToken, requirePermissions(...perms)];
}

module.exports = {
  requireRole,
  requirePermissions,
  requireAnyPermission,
  requireOwnership,
  guard,
  guardWithPermissions,
  VALID_ROLES,
  ROLE_PERMISSIONS,
};