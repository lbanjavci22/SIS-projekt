const bcrypt = require('bcrypt');

// demo korisnici – lozinke ćemo hashirati pri startu
let users = [
  { id: 1, username: 'doctor1',  password: 'doctorpass',  role: 'doctor' },
  { id: 2, username: 'patient1', password: 'patientpass', role: 'patient' },
  { id: 3, username: 'patient2', password: 'patientpass', role: 'patient' },
];


const saltRounds = 10;
users = users.map((u) => ({
  ...u,
  password: bcrypt.hashSync(u.password, saltRounds),
}));

console.log('Hashirani korisnici:', users);

module.exports = { users, bcrypt };
