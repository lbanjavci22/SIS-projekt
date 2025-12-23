const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const authRoutes = require('./routes/authRoutes');
const recordsRoutes = require('./routes/recordsRoutes');

const app = express();

app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(helmet());
app.use(express.json());


app.get('/', (req, res) => {
  res.send('API radi');
});


app.use('/api', authRoutes);         
app.use('/api/records', recordsRoutes);

module.exports = app;
