const db = require('../db');

function getAllRecords() {
  const stmt = db.prepare('SELECT id, patientName, diagnosis FROM records');
  return stmt.all();
}

function addRecord(patientName, diagnosis) {
  const insert = db.prepare(
    'INSERT INTO records (patientName, diagnosis) VALUES (?, ?)'
  );
  const info = insert.run(patientName, diagnosis);

  return {
    id: info.lastInsertRowid,
    patientName,
    diagnosis,
  };
}

function updateRecord(id, patientName, diagnosis) {
  const update = db.prepare(
    'UPDATE records SET patientName = ?, diagnosis = ? WHERE id = ?'
  );
  const info = update.run(patientName, diagnosis, id);

  return info.changes > 0;
}


function deleteRecord(id) {
  const del = db.prepare('DELETE FROM records WHERE id = ?');
  const info = del.run(id);
  return info.changes > 0;
}

module.exports = {
  getAllRecords,
  addRecord,
  updateRecord,
  deleteRecord,
};
