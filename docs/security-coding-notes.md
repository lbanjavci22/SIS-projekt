# Sigurnosne mjere u kodu

## 1. Broken Access Control


Broken Access Control opisuje situacije kada korisnik može pristupiti podacima ili funkcijama koje mu po pravilima ne bi smio, npr. pacijent vidi tuđe nalaze, neprijavljen korisnik vidi “interni” portal ili običan korisnik može raditi radnje rezervirane za doktora/admina. U početnoj verziji naše aplikacije upravo je to bio slučaj: svi su mogli vidjeti sve “zdravstvene zapise” i dodavati nove zapise bez ikakve prijave i provjere uloge, što je klasičan primjer Broken Access Control u zdravstvenom kontekstu.

***

### Početno stanje (namjerno nesigurno)

- Endpointi `/api/records` (GET i POST) bili su javno dostupni bez autentikacije.
- Svatko tko otvori frontend mogao je vidjeti sve “pacijente” i dijagnoze.
- Nije bilo razlike između pacijenta i doktora – svi su imali iste mogućnosti.
- Nije postojao nikakav mehanizam za provjeru “vlasništva” nad zapisom (record ownership).

Ovo je direktno kršenje principa “least privilege” i “deny by default” – pristup je bio omogućen svima, umjesto da bude ograničen samo na legitimne korisnike i odgovarajuće uloge.

***

### Uvedeni koncepti za rješavanje Broken Access Control

#### 1. Uvođenje korisnika i uloga (RBAC)

Definirani su demo korisnici s različitim ulogama u `src/models/users.js`:

```js
let users = [
  { id: 1, username: 'doctor1',  password: 'doctorpass',  role: 'doctor' },
  { id: 2, username: 'patient1', password: 'patientpass', role: 'patient' },
  { id: 3, username: 'patient2', password: 'patientpass', role: 'patient' },
];
```

- Uloga `doctor` predstavlja korisnika koji može vidjeti i uređivati sve zapise.
- Uloga `patient` predstavlja korisnika koji smije vidjeti samo “svoje” medicinske zapise.
- Ovo je osnova za role‑based access control (RBAC): pravila pristupa više ne ovise samo o tome je li korisnik “prijavljen”, nego i o tome koju ulogu ima.


#### 2. Login i sesijski token

Dodan je login endpoint u `src/routes/authRoutes.js`:

```js
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  // ...
  const user = users.find((u) => u.username === username);
  // provjera lozinke, rate limit, itd.
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
```

Uz pomoć `createSession` u `authMiddleware`:

```js
const sessions = {}; // token -> user info

function createSession(user) {
  const token = crypto.randomBytes(16).toString('hex');
  sessions[token] = {
    id: user.id,
    username: user.username,
    role: user.role,
  };
  return token;
}
```

- Svaki uspješan login generira jedinstveni sesijski token.
- Token se sprema u memoriju (session store) zajedno s identitetom i ulogom korisnika.
- Frontend token šalje u `Authorization: Bearer <token>` headeru pri svakom API pozivu.

Time prelazimo s “svi su anonimni” na “svaki zahtjev je povezan s konkretnim korisnikom i ulogom”.

***

### Centralizirana kontrola pristupa u backendu

#### 3. Middleware za autentikaciju

U `src/middleware/authMiddleware.js` definiran je `authMiddleware`:

```js
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

  req.user = sessionUser; // { id, username, role }
  next();
}
```

- Za svaki zaštićeni endpoint provjerava postoji li `Authorization` header s valjanim tokenom.
- Ako token nije ispravan ili ne postoji → `401 Unauthorized` i dalje se ne ide.
- Ako je token valjan, `req.user` dobiva podatke o korisniku, što omogućuje kasniju provjeru uloge i vlasništva.


#### 4. Middleware za ulogu (requireRole)

Dodan je i `requireRole` helper:

```js
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
```

- Osigurava da samo korisnici s određenom ulogom mogu izvršiti određene akcije.
- Ako uloga ne odgovara, vraća `403 Forbidden` (korisnik je autentificiran, ali nema ovlasti).

***

### Primjena kontrola pristupa na API rute

#### 5. Zaštita čitanja zapisa (GET /api/records)

U `src/routes/recordsRoutes.js`:

```js
router.get('/', authMiddleware, (req, res) => {
  const records = getAllRecords();
  res.json(records);
});
```

- Ruta više nije javna – zahtijeva `authMiddleware`.
- Neprijavljeni korisnik više ne može vidjeti ni jedan medicinski zapis.
- Na frontend‑u, lista se učitava tek nakon uspješne prijave (kada postoji token).

Dodatno, na frontendu se vidljivost lista filtrira po ulozi i korisniku:

```js
{records
  .filter((r) => {
    if (currentUser?.role === 'patient') {
      const allowedRecordId = currentUser.id - 1;
      return r.id === allowedRecordId;
    }
    return true; // doctor vidi sve
  })
  .map(...)}
```

- `patient1` (id=2) vidi samo zapis s `id=1`.
- `patient2` (id=3) vidi samo zapis s `id=2`.
- `doctor1` vidi sve.

To demonstrira koncept “record ownership” – pacijent ne dobiva pristup tuđim zapisima čak ni kroz UI.

#### 6. Zaštita stvaranja, uređivanja i brisanja zapisa

Sve mutirajuće operacije na zapisima (POST, PUT, DELETE) zaštićene su dvostrukom kontrolom: prvo autentikacija, zatim provjera uloge:

```js
// POST /api/records – samo doctor
router.post('/', authMiddleware, requireRole('doctor'), (req, res) => {
  const { patientName, diagnosis } = req.body;
  // ...
  const newRecord = addRecord(patientName, diagnosis);
  res.status(201).json(newRecord);
});

// PUT /api/records/:id – samo doctor
router.put('/:id', authMiddleware, requireRole('doctor'), (req, res) => {
  // ...
});

// DELETE /api/records/:id – samo doctor
router.delete('/:id', authMiddleware, requireRole('doctor'), (req, res) => {
  // ...
});
```

- Neprijavljeni korisnici ne mogu ni čitati ni mijenjati podatke.
- Prijavljeni korisnici s ulogom `patient` mogu čitati samo vlastite zapise (filter u frontendu, a u realnom sustavu bi se to dodatno provjeravalo u backendu).
- Samo `doctor` može stvarati, uređivati i brisati zapise – svi drugi dobivaju `403 Forbidden`.

***

### Uloga frontenda u sprječavanju zloupotrebe

Frontend sam po sebi nije sigurnosna barijera (sve ključne kontrole su u backendu), ali pomaže UX‑u:

- Forma “Dodaj/uredi/obriši zapis” renderira se samo ako `currentUser.role === 'doctor'`.
- Pacijentu se u UI‑ju ni ne nude opcije koje ne smije koristiti, što smanjuje površinu za slučajne greške i jasno pokazuje granice uloga.

Primjer:

```jsx
{currentUser?.role === 'doctor' && (
  <section className="card">
    <h2>Dodaj ili uredi zapis (samo doktor)</h2>
    {/* forma */}
  </section>
)}
```


***

### Sažetak – kako smo ispravili Broken Access Control

- **Prije**: svi korisnici (ili posjetitelji bez prijave) mogli su vidjeti i mijenjati sve zapise, bez ikakve provjere identiteta i uloge.
- **Sada**:
    - uveden je login s tokenom i sessionima, pa je svaki zahtjev vezan uz konkretnog korisnika
    - centralni `authMiddleware` osigurava da zaštićeni endpointi rade samo za prijavljene korisnike
    - `requireRole` implementira RBAC – npr. samo `doctor` smije mijenjati podatke
    - logika u frontendu i backendu demonstrira “record ownership” – pacijenti vide samo “svoje” zapise (npr. Frontend uvijek šalje token u `Authorization` headeru i prikazuje formu za dodavanje zapisa samo ako je uloga `doctor`, što vizualno prati pravila pristupa)
    - rutama se pristupa po principu “deny by default”: bez tokena/role → nema pristupa.

Ovim pristupom aplikacija više ne pati od Broken Access Control u osnovnim scenarijima, a kod i arhitektura jasno pokazuju gdje se i kako provode kontrole pristupa.


## 2. Security Misconfiguration

Security Misconfiguration se događa kada aplikacija ili okruženje nisu dobro podešeni sa sigurnosnog stajališta, npr. dopuštaju preširoki pristup, imaju default postavke ili ne šalju sigurnosne HTTP headere. U takvim slučajevima sustav postaje ranjiv iako je sam kod možda ispravan.

U našem projektu adresirali smo Security Misconfiguration na nekoliko ključnih mjesta:

***

### Ograničeni CORS

Umjesto da dopuštamo zahtjeve s bilo kojeg origin-a, CORS je ograničen isključivo na frontend aplikaciju (`http://localhost:3000`):

```js
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
```

Na taj način API ne mogu koristiti proizvoljne web stranice iz browsera, nego samo naš kontrolirani frontend. Ovo smanjuje rizik pogrešne konfiguracije koja bi dopustila neovlaštenim originima pristup API-ju.

***

### Sigurnosni HTTP headeri (helmet)

Dodavanjem `helmet()` middleware-a centralno smo uključili set sigurnosnih HTTP headera:

```js
const helmet = require('helmet');

app.use(helmet());
```

To automatski dodaje, između ostalog:

- `Content-Security-Policy` – ograničava izvore skripti, stilova, slika itd.
- `X-Frame-Options` – sprječava učitavanje aplikacije u iframe (clickjacking zaštita).
- `X-Content-Type-Options` – sprječava “pogađanje” tipa sadržaja (MIME sniffing).
- `Referrer-Policy`, `X-DNS-Prefetch-Control`, `Strict-Transport-Security` (u produkciji) i druge headere.

Time smo izbjegli tipičnu misconfiguraciju u kojoj server ne šalje nikakve sigurnosne directive prema browseru.

***

### Demo korisnici i konfiguracije u dokumentaciji

Korisnici `doctor1/patient1/patient2` i njihove lozinke postoje samo kao razvojni/demo podaci. U dokumentaciji jasno navodimo da bi se u stvarnom okruženju:

- korisnici i lozinke nalazili u bazi
- lozinke bile hashirane i jake
- default računi i lozinke bili uklonjeni ili promijenjeni
- konfiguracija (CORS, portovi, ključevi) dolazila iz environment varijabli različitih po okruženju (dev/test/prod).

Na taj način pokazujemo da razumijemo rizik “default credova” i loše konfiguracije, čak i ako u demo kodu koristimo pojednostavljene postavke radi učenja.



## 3. SQL injection
SQL injection (SQLi) je napad kod kojeg napadač ubacuje zlonamjerni SQL u upite koje aplikacija sastavlja iz korisničkog inputa. Ako se upiti grade spajanjem stringova, napadač može promijeniti logiku upita, čitati tuđe podatke ili čak obrisati cijele tablice.

***

### Loš primjer (ranjiv pristup)

U ovakvom “lošem” kodu user input ide direktno u SQL string:

```js
// PRIMJER – NE KORISTITI
const name = req.query.name; // npr. iz URL-a ?name=Ana
const sql = "SELECT id, patientName, diagnosis FROM records WHERE patientName = '" + name + "'";

const rows = db.prepare(sql).all();
```

Ako napadač pošalje `name` poput:
`Ana' OR '1'='1`
upit postaje:

```sql
SELECT id, patientName, diagnosis FROM records
WHERE patientName = 'Ana' OR '1'='1'
```

i vraća sve zapise umjesto jednog. Isto se može iskoristiti za teže napade (brisanje, izmjenu podataka), ovisno o mogućnostima baze.

***

### Dobar primjer (parametrizirani upiti – naš pristup)

U našem projektu ne spajamo stringove, nego koristimo parametrizirane upite s `?` placeholderima:

```js
// models/records.js

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
```

Ključne razlike:

- SQL naredba je fiksna, a korisničke vrijednosti prolaze kao parametri (`?`), ne kao dio samog SQL stringa.
- SQLite driver sam “escape-a” i veže vrijednosti na siguran način, pa user input ne može “izaći” iz parametra i promijeniti strukturu upita.
- Isti princip vrijedi za `SELECT`, `INSERT`, `UPDATE` i `DELETE` – uvijek se koriste placeholderi i zasebni parametri.

Na ovaj način pokazujemo da smo svjesni SQL injection rizika i da ga rješavamo standardnom i preporučenom praksom: parametriziranim upitima umjesto ručnog spajanja stringova.

## 4. Authentication Failures


Authentication Failures se u praksi događaju kada aplikacija slabo štiti prijavu: lozinke su prejednostavne ili u čistom tekstu, nema ograničenja pokušaja, poruke odaju previše informacija (“user ne postoji”), a sesije se lako zloupotrebljavaju. U početnoj verziji naše aplikacije imali smo vrlo jednostavan login bez zaštite: lozinke su bile u čistom tekstu, broj pokušaja prijave nije bio ograničen i nije bilo nikakvog mehanizma koji bi otežao brute-force ili ponovnu upotrebu kompromitiranih vjerodajnica.

U ovoj fazi cilj je bio pokazati kako se ovaj problem adresira u studentskom projektu kroz tri konkretne mjere: hashiranje lozinki, osnovnu zaštitu od brute-force napada i pažljivo oblikovane poruke pri prijavi.

***

### Hashiranje lozinki

Umjesto da lozinke ostanu u čistom tekstu u memoriji (“doctorpass”, “patientpass”), sada se pri pokretanju backend-a lozinke hashiraju pomoću bcrypt algoritma, a login uspoređuje korisnički unos s hashiranom vrijednošću.

Ključni dio u `src/models/users.js`:

```js
const bcrypt = require('bcrypt');

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

module.exports = { users, bcrypt };
```

Time:

- u datoteci imamo “seed” lozinke radi jednostavnosti razvoja
- u runtime-u (`users` nakon mapiranja) lozinke više nisu “doctorpass”, već bcrypt hash stringovi (`$2b$...`), pa eventualni pristup memoriji ne otkriva stvarne lozinke
- login kasnije koristi `bcrypt.compareSync` umjesto usporedbe čistih stringova, što je standardna zaštita u stvarnim sustavima.

***

### Osnovna zaštita od brute-force napada

Da bismo spriječili beskonačno isprobavanje lozinki za jednog korisnika (brute force / credential stuffing), dodana je jednostavna zaštita koja ograničava broj neuspješnih pokušaja prijave u kratkom vremenu. Za svaki `username` pratimo broj pokušaja i vrijeme zadnjeg pokušaja, i nakon određenog praga privremeno blokiramo daljnje logine.

Ključni dio u `src/routes/authRoutes.js`:

```js
const express = require('express');
const { users, bcrypt } = require('../models/users');
const { createSession } = require('../middleware/authMiddleware');

const router = express.Router();

// jednostavan "rate limit" po korisničkom imenu
// mapa: username -> { attempts, lastAttempt }
const loginAttempts = {};
const MAX_ATTEMPTS = 5;
const BLOCK_WINDOW_MS = 1 * 60 * 1000; // 1 minuta

router.post('/login', (req, res) => {
  const { username, password } = req.body;

  const now = Date.now();
  const attemptsInfo = loginAttempts[username] || { attempts: 0, lastAttempt: 0 };

  // reset pokušaja ako je prošla blok-špica
  if (now - attemptsInfo.lastAttempt > BLOCK_WINDOW_MS) {
    attemptsInfo.attempts = 0;
  }

  // previše pokušaja u zadnjoj minuti -> privremeno blokiraj
  if (attemptsInfo.attempts >= MAX_ATTEMPTS && now - attemptsInfo.lastAttempt <= BLOCK_WINDOW_MS) {
    return res
      .status(429)
      .json({ message: 'Previše pokušaja prijave. Pokušajte kasnije.' });
  }

  attemptsInfo.lastAttempt = now;
  loginAttempts[username] = attemptsInfo;

  const user = users.find((u) => u.username === username);

  // generička poruka, ne otkriva postoji li korisnik
  if (!user) {
    attemptsInfo.attempts += 1;
    loginAttempts[username] = attemptsInfo;
    return res
      .status(401)
      .json({ message: 'Neispravno korisničko ime ili lozinka.' });
  }

  const passwordOk = bcrypt.compareSync(password, user.password);

  if (!passwordOk) {
    attemptsInfo.attempts += 1;
    loginAttempts[username] = attemptsInfo;
    return res
      .status(401)
      .json({ message: 'Neispravno korisničko ime ili lozinka.' });
  }

  // uspješna prijava – resetiraj broj pokušaja
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
```

Ovim:

- nakon 5 neuspjelih pokušaja u jednoj minuti vraća se `429 Too Many Requests` i poruka da je previše pokušaja prijave
- ako prođe blok-vremenski prozor (ovdje 1 minuta), brojač se resetira i korisnik može ponovno pokušati
- pokazujemo koncept zaštite od brute-force napada i credential stuffing-a, iako u malom demo okruženju.

***

### Ujednačene poruke pri loginu

Važan detalj kod Authentication Failures je da login ne smije odavati “previše informacija” (npr. “korisnik ne postoji” vs. “lozinka je kriva”), jer to olakšava napadaču da radi account enumeration. U našoj implementaciji:

- za sve neuspjele prijave (bilo da korisnik ne postoji, bilo da je lozinka kriva) API vraća istu poruku:

```js
return res
  .status(401)
  .json({ message: 'Neispravno korisničko ime ili lozinka.' });
```

- frontend prikazuje ovu poruku kroz `loginError` state:

```js
.catch((err) => {
  console.error('Greška pri prijavi:', err);
  setLoginError(err.message);
});
```

Na taj način korisnik dobiva jasnu, ali generičku poruku, dok napadač ne može razlikovati postoji li odabrani `username` ili ne, što je preporučena praksa (hardened registration / credential recovery / login protiv account enumeration-a).

***

### Sažetak dodanih mjera

Za “Authentication Failures” u ovom projektu implementirane su sljedeće konkretne mjere:

- Lozinke se više ne pohranjuju ni uspoređuju u čistom tekstu, već se pri pokretanju backend-a hashiraju bcryptom i uspoređuju preko `bcrypt.compareSync`, čime se uklanja rizik krađe plain-text lozinki iz memorije.
- Uveden je jednostavan, ali efektivan limit broja neuspjelih login pokušaja po korisničkom imenu u vremenskom prozoru (rate limiting), čime se otežavaju brute-force i credential stuffing napadi.
- Sve neuspjele prijave (nepostojeći korisnik ili kriva lozinka) vraćaju istu generičku poruku, kako bi se spriječilo otkrivanje informacija o postojanju korisničkih računa i smanjio rizik account enumeration napada.

Ove promjene, zajedno s već postojećim mehanizmima (token-based session, RBAC, zaštićene rute), pokazuju da je autentikacija u aplikaciji promišljena u skladu s OWASP preporukama, čak i u sklopu malog studentskog projekta.

## 5. Insecure design

Insecure design označava situaciju u kojoj sigurnosne kontrole uopće nisu dobro osmišljene – ne radi se o “bugu u kodu”, nego o tome da sigurnost nije bila ugrađena u zahtjeve, dizajn i proces razvoja. U takvom slučaju ni savršena implementacija ne može pomoći, jer ključne zaštite jednostavno ne postoje.

U našem projektu ovaj problem rješavamo na razini **cijelog SDLC‑a**, a ne jednim trikom u kodu:

- **Faza 1 – zahtjevi i model prijetnji**
    - Jasno definiramo da radimo s osjetljivim zdravstvenim podacima (PHI) i da su prioriteti povjerljivost, integritet i ograničavanje pristupa.
    - U zahtjeve upisujemo obaveznu autentikaciju, razdvajanje uloga (doctor/patient), ograničavanje pristupa na “vlastite” zapise, logging pristupa i zaštitu od tipičnih napada (SQLi, brute force, itd.).
    - Threat model identificira realne napade (npr. pacijent koji pokušava vidjeti tuđe nalaze, napadač koji pogađa lozinke, SQL injection na API).
- **Faza 2 – sigurni dizajn arhitekture i logike**
    - Dizajniramo arhitekturu s backend API-jem, odvojenim frontendom, ograničenim CORS‑om i konceptom “record ownership” (pacijent vidi samo svoje zapise, doktor vidi sve).
    - Planiramo centralni sloj za autentikaciju i kontrolu pristupa (middleware, RBAC), umjesto da se provjere rade slučajno po kodu.
    - Definiramo da se za pohranu koristi SQL baza, s parametriziranim upitima umjesto konkatenacije stringova, kako bismo dizajnom uklonili SQL injection.
- **Faze 3–4 – implementacija i testiranje prema dizajnu**
    - Implementiramo dizajnirane kontrole: login, hashiranje lozinki, role‑based access control (auth middleware + requireRole), SQLite s parametriziranim upitima, ograničen CORS, helmet headeri i rate limit na login.
    - U testiranju provjeravamo kritične tokove:
        - neautentificirani korisnik ne vidi zapise niti ih može mijenjati
        - patient1/patient2 vide samo “svoje” zapise
        - samo doctor smije dodavati/uređivati/brisati zapise
        - čudni inputi se spremaju kao tekst, a ne mijenjaju SQL upite.
- **Faze 5–6 – deployment i održavanje (konceptualno)**
    - U dokumentaciji opisujemo kako bi se isti sigurnosni dizajn prenio u stvarno okruženje: sigurni headeri, ograničen pristup API‑ju, korištenje hashiranih lozinki u bazi, različite konfiguracije po okruženju, plan za patchanje i incident response.
    - Time pokazujemo da sigurnost nije jednokratna odluka, nego dio procesa održavanja i budućih promjena.

Sažeto: umjesto da imamo “Insecure Design” (aplikacija bez jasno definiranih sigurnosnih zahtjeva i kontrola), projekt je od početka vođen kao **secure‑by‑design**: prijetnje su razmotrene u fazi zahtjeva, sigurnosne kontrole su planirane u dizajnu, provedene u implementaciji i uzete u obzir u testiranju i održavanju.


## 6. Cryptographic Failures

Cryptographic Failures (bivši “Sensitive Data Exposure”) nastaju kada se osjetljivi podaci ne šifriraju ispravno, koriste se slabi algoritmi ili se ključevi loše čuvaju. U našem demo projektu koristimo običan HTTP, lozinke u čistom tekstu i nema enkripcije podataka u bazi, što je prihvatljivo samo zato što se radi o edukativnom primjeru bez stvarnih korisnika i pravih zdravstvenih zapisa.

### Što bismo napravili u produkciji

U stvarnoj verziji ove aplikacije, koja obrađuje zdravstvene podatke, poduzeli bismo sljedeće korake:

- Sav promet bi išao preko HTTPS‑a (TLS 1.2/1.3), uz valjan certifikat (npr. Let’s Encrypt) i HSTS kako bi se prisililo korištenje šifrirane veze.
- Lozinke bi se pohranjivale samo u obliku hash vrijednosti, koristeći jake adaptivne funkcije (Argon2, bcrypt ili PBKDF2) sa saltom i dovoljno velikim “work factorom”.
- Osjetljiva polja u bazi (npr. dijagnoza, zdravstveni nalazi, osobni podaci) bila bi šifrirana “at rest” uz moderne, provjerene algoritme (npr. AES‑GCM), pri čemu se ključevi ne bi nalazili u kodu nego u HSM‑u ili cloud KMS‑u, s jasnim pravilima rotacije i pristupa.
- Svi tajni podaci (ključevi, lozinke za baze, API ključevi) držali bi se u sigurnom storageu (environment varijable + secret manager), a ne u repozitoriju, uz automatske provjere da tajne ne završe u verzioniranom kodu.
- Na razini konfiguracije servera uključili bismo moderne TLS postavke, zabranili zastarjele protokole/šifre i dodali sigurnosne HTTP headere (npr. HSTS, no‑cache za osjetljive odgovore) kako bismo spriječili downgrade napade i curenje podataka kroz cache.


### Kako se to odražava u ovom projektu

U ovoj edukativnoj aplikaciji te mjere ne provodimo do kraja kako bismo zadržali fokus na drugim OWASP kategorijama (Broken Access Control, Insecure Design, Security Misconfiguration). Umjesto toga, u dokumentaciji jasno naglašavamo:

- da trenutna implementacija kriptografije nije primjer za produkciju
- koje konkretne promjene bi bile potrebne da aplikacija zadovolji zahtjeve za enkripciju u tranzitu i mirovanju, sigurno pohranjivanje lozinki i ispravan key‑management

Na taj način “Cryptographic Failures” nisu u potpunosti riješeni u kodu, ali je u dokumentaciji jasno prikazano razumijevanje problema i plan kako bi se oni adresirali u stvarnom, produkcijskom okruženju.
