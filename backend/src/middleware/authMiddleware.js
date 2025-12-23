const crypto = require('crypto');

const sessions = {};

function createSession(user) {
  const token = crypto.randomBytes(16).toString('hex');
  sessions[token] = {
    id: user.id,
    username: user.username,
    role: user.role,
  };
  return token;
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Niste prijavljeni' });
  }

  const token = authHeader.replace('Bearer ', '').trim();
  const sessionUser = sessions[token];

  if (!sessionUser) {
    return res.status(401).json({ message: 'Nevažeća ili istekla sesija' });
  }

  req.user = sessionUser;
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Niste prijavljeni' });
    }
    if (req.user.role !== role) {
      return res.status(403).json({ message: 'Nemate pravo za ovu akciju' });
    }
    next();
  };
}

module.exports = {
  authMiddleware,
  requireRole,
  createSession,
};
