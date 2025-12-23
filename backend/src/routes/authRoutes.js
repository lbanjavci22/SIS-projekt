const express = require('express');
const { users, bcrypt } = require('../models/users');
const { createSession } = require('../middleware/authMiddleware');

const router = express.Router();

const loginAttempts = {};
const MAX_ATTEMPTS = 5;
const BLOCK_WINDOW_MS = 1 * 10 * 1000; // 10 sek

router.post('/login', (req, res) => {
  const { username, password } = req.body;

  const now = Date.now();
  const attemptsInfo = loginAttempts[username] || { attempts: 0, lastAttempt: 0 };

  // resetiranje brojača
  if (now - attemptsInfo.lastAttempt > BLOCK_WINDOW_MS) {
    attemptsInfo.attempts = 0;
  }

  // ako je već previše pokušaja u zadnjoj minuti, blokiraj privremeno
  if (attemptsInfo.attempts >= MAX_ATTEMPTS && now - attemptsInfo.lastAttempt <= BLOCK_WINDOW_MS) {
    return res.status(429).json({ message: 'Previše pokušaja prijave. Pokušajte kasnije.',
      retryAfterMs: BLOCK_WINDOW_MS,
     });
  }

  attemptsInfo.lastAttempt = now;
  loginAttempts[username] = attemptsInfo;

  const user = users.find((u) => u.username === username);

  // generička poruka
  if (!user) {
    attemptsInfo.attempts += 1;
    loginAttempts[username] = attemptsInfo;
    return res.status(401).json({ message: 'Prijava nije uspjela. Provjerite korisničko ime i lozinku.' });
  }

  const passwordOk = bcrypt.compareSync(password, user.password);

  if (!passwordOk) {
    attemptsInfo.attempts += 1;
    loginAttempts[username] = attemptsInfo;
    return res.status(401).json({ message: 'Prijava nije uspjela. Provjerite korisničko ime i lozinku.' });
  }

  // uspješna prijava
  loginAttempts[username] = { attempts: 0, lastAttempt: now };

  const token = createSession(user);

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
    },
  });
});

module.exports = router;
