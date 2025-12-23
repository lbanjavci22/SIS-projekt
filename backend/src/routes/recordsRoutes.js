const express = require('express');
const {
  getAllRecords, addRecord, updateRecord, deleteRecord} = require('../models/records');
const { authMiddleware, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();

router.get('/', authMiddleware, (req, res) => {
  const records = getAllRecords();
  res.json(records);
});

router.post('/', authMiddleware, requireRole('doctor'), (req, res) => {
  const { patientName, diagnosis } = req.body;

  if (!patientName || !diagnosis) {
    return res.status(400).json({ message: 'Nedostaju podaci' });
  }

  const newRecord = addRecord(patientName, diagnosis);
  res.status(201).json(newRecord);
});


router.put('/:id', authMiddleware, requireRole('doctor'), (req, res) => {
  const { id } = req.params;
  const { patientName, diagnosis } = req.body;

  if (!patientName || !diagnosis) {
    return res.status(400).json({ message: 'Nedostaju podaci' });
  }

  const ok = updateRecord(Number(id), patientName, diagnosis);
  if (!ok) {
    return res.status(404).json({ message: 'Zapis nije pronađen' });
  }

  res.json({ id: Number(id), patientName, diagnosis });
});


router.delete('/:id', authMiddleware, requireRole('doctor'), (req, res) => {
  const { id } = req.params;

  const ok = deleteRecord(Number(id));
  if (!ok) {
    return res.status(404).json({ message: 'Zapis nije pronađen' });
  }

  res.status(204).send();
});

module.exports = router;
