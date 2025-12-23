const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', '..', 'healthcare.db');
const db = new Database(dbPath);

db.prepare(`
  CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patientName TEXT NOT NULL,
    diagnosis TEXT NOT NULL
  )
`).run();

const rowCount = db.prepare('SELECT COUNT(*) as count FROM records').get().count;
if (rowCount === 0) {
  const insert = db.prepare('INSERT INTO records (patientName, diagnosis) VALUES (?, ?)');
  insert.run('Ana Pacijent', 'Prehlada');
  insert.run('Marko Pacijent', 'Gripa');
  insert.run('Ivana Novak', 'Povišeni krvni tlak');
  insert.run('Petar Horvat', 'Kontrola nakon operacije koljena');
  insert.run('Maja Kovač', 'Alergijski rinitis');
  insert.run('Luka Babić', 'Dijabetes tip 2');
}

module.exports = db;
