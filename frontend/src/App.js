import React, { useEffect, useState } from 'react';
import './App.css';

function App() {
  const [records, setRecords] = useState([]);
  const [showDashboard, setShowDashboard] = useState(false);
  const [patientName, setPatientName] = useState('');
  const [diagnosis, setDiagnosis] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [isBlocked, setIsBlocked] = useState(false);
  const [lockoutMsRemaining, setLockoutMsRemaining] = useState(0);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [loginError, setLoginError] = useState('');

  useEffect(() => {
    if (!showDashboard || !token) return;

    fetch('http://localhost:4000/api/records', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => {
        if (!res.ok) {
          throw new Error('Neuspješan dohvat zapisa');
        }
        return res.json();
      })
      .then((data) => setRecords(data))
      .catch((err) => console.error('Greška pri dohvaćanju:', err));
  }, [showDashboard, token]);

  useEffect(() => {
    if (!lockoutMsRemaining) return;

    const interval = setInterval(() => {
      setLockoutMsRemaining((prev) => {
        const next = prev - 1000;
        return next > 0 ? next : 0;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [lockoutMsRemaining]);

  useEffect(() => {
    if (lockoutMsRemaining === 0 && isBlocked) {
      setIsBlocked(false);
    }
  }, [lockoutMsRemaining, isBlocked]);


  const handleLogin = (e) => {
    e.preventDefault();
    setLoginError('');
    setIsSubmitting(true);

    fetch('http://localhost:4000/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
      .then(async (res) => {
        const data = await res.json().catch(() => ({}));

        if (!res.ok) {
          if (res.status === 429) {
            const ms = data.retryAfterMs || 0;
            if (ms > 0) {
              setIsBlocked(true);
              setLockoutMsRemaining(ms);
            }

            throw new Error(
              data.message || 'Previše pokušaja prijave. Pokušajte kasnije.'
            );
          }

          throw new Error(
            data.message ||
              'Prijava nije uspjela. Provjerite korisničko ime i lozinku.'
          );
        }

        return data;
      })
      .then((data) => {
        setToken(data.token);
        setCurrentUser(data.user);
        setShowDashboard(true);
        setUsername('');
        setPassword('');
        setIsBlocked(false);
        setLockoutMsRemaining(0);
      })
      .catch((err) => {
        console.error('Greška pri prijavi:', err);
        setLoginError(err.message);
      })
      .finally(() => {
        setIsSubmitting(false);
      });
  };




  const handleLogout = () => {
    setToken(null);
    setCurrentUser(null);
    setRecords([]);
    setShowDashboard(false);
  };

  const handleSubmit = (e) => {
  e.preventDefault();
  if (!patientName.trim() || !diagnosis.trim() || !token) return;

  setIsSubmitting(true);

  const method = editingId ? 'PUT' : 'POST';
  const url = editingId
    ? `http://localhost:4000/api/records/${editingId}`
    : 'http://localhost:4000/api/records';

  fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ patientName, diagnosis }),
  })
    .then((res) => {
      if (!res.ok) {
        throw new Error('Greška pri spremanju');
      }
      return editingId ? res.json() : res.json();
    })
    .then((saved) => {
      if (editingId) {
        setRecords((prev) =>
          prev.map((r) => (r.id === saved.id ? saved : r))
        );
      } else {
        setRecords((prev) => [...prev, saved]);
      }
      setPatientName('');
      setDiagnosis('');
      setEditingId(null);
    })
    .catch((err) => {
      console.error('Greška pri spremanju:', err);
      alert('Spremanje nije uspjelo (možda nemate potrebna prava).');
    })
    .finally(() => setIsSubmitting(false));
  };

  const startEdit = (record) => {
    setEditingId(record.id);
    setPatientName(record.patientName);
    setDiagnosis(record.diagnosis);
  };

  const handleDelete = (id) => {
    if (!window.confirm('Sigurno želite obrisati ovaj zapis?')) return;
    if (!token) return;

    fetch(`http://localhost:4000/api/records/${id}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => {
        if (res.status === 204) {
          setRecords((prev) => prev.filter((r) => r.id !== id));
        } else {
          throw new Error('Greška pri brisanju');
        }
      })
      .catch((err) => {
        console.error('Greška pri brisanju:', err);
        alert('Brisanje nije uspjelo.');
      });
  };

  if (!token) {
    return (
      <div className="landing">
        <h1 className="title">Demo zdravstvena aplikacija</h1>
        <p className="subtitle">
          Prijavite se kao doctor1/doctorpass ili patient1/patientpass.
        </p>
        <form className="login-form" onSubmit={handleLogin}>
          <div className="form-row">
            <label>Korisničko ime</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="npr. doctor1"
            />
          </div>
          <div className="form-row">
            <label>Lozinka</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="npr. doctorpass"
            />
          </div>
          {loginError && <p className="error-text">{loginError}</p>}
          {lockoutMsRemaining > 0 && (
            <p className="error-text">
              Možete ponovno pokušati za{' '}
              {Math.ceil(lockoutMsRemaining / 1000)} sekundi.
            </p>
          )}
          <button className="primary-button" type="submit" disabled={isSubmitting || isBlocked}>
            Prijava
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="header">
        <div>
          <h1>Portal zdravstvenih zapisa</h1>
          {currentUser && (
            <p className="user-info">
              Prijavljeni ste kao <strong>{currentUser.username}</strong> (uloga:{' '}
              <strong>{currentUser.role}</strong>)
            </p>
          )}
        </div>
        <button className="secondary-button" onClick={handleLogout}>
          Odjava
        </button>
      </header>

      {currentUser?.role === 'doctor' && (
        <section className="card">
          <h2>{editingId ? 'Uredi zapis' : 'Dodaj novi zapis (samo doktor)'}</h2>
            <form className="record-form" onSubmit={handleSubmit}>
            <div className="form-row">
              <label>Ime pacijenta</label>
              <input
                type="text"
                value={patientName}
                onChange={(e) => setPatientName(e.target.value)}
                placeholder="npr. Ivana Novak"
              />
            </div>
            <div className="form-row">
              <label>Dijagnoza / bilješka</label>
              <input
                type="text"
                value={diagnosis}
                onChange={(e) => setDiagnosis(e.target.value)}
                placeholder="npr. Kontrola krvnog tlaka"
              />
            </div>
            <button className="primary-button" type="submit" disabled={isSubmitting}>
              {isSubmitting ? 'Spremam...' : 'Spremi zapis'}
            </button>
          </form>
        </section>
      )}

      <section className="card">
        <h2>Medicinski zapisi (demo)</h2>
        <p className="help-text">
          Ovo je demo prikaz - pristup je sada ograničen samo na prijavljene korisnike.
        </p>
        <ul className="record-list">
          {records
            .filter((r) => {
              if (currentUser?.role === 'patient') {
                const allowedRecordId = currentUser.id - 1;
                return r.id === allowedRecordId;
              }
              return true;
            })
            .map((r) => (
              <li key={r.id} className="record-item">
                <div className="record-text">
                  <div className="record-name">{r.patientName}</div>
                  <div className="record-diagnosis">{r.diagnosis}</div>
                </div>
                {currentUser?.role === 'doctor' && (
                  <div className="record-actions">
                    <button
                      type="button"
                      className="small-button"
                      onClick={() => startEdit(r)}
                    >
                      Uredi
                    </button>
                    <button
                      type="button"
                      className="small-button danger"
                      onClick={() => handleDelete(r.id)}
                    >
                      Obriši
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>


      </section>
    </div>
  );
}

export default App;
