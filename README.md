U ovom projektu implementirana je demo web-aplikacija za upravljanje zdravstvenim zapisima koja služi kao praktičan primjer sigurnog razvoja softvera prema principima OWASP Top 10 i sigurnog životnog ciklusa razvoja (SDLC). Aplikacija je podijeljena na frontend (React) i backend (Node.js/Express) te koristi SQLite bazu podataka za pohranu medicinskih zapisa.

## Što je implementirano i zašto

U projektu napravit će se sljedeće ključne sigurnosne mjere i funkcionalnosti:

- Uvedena je autentikacija i autorizacija s ulogama `doctor` i `patient`, kako bi se spriječilo da svi korisnici imaju isti pristup podacima (rješavanje Broken Access Control).
- Implementiran je login s dodjelom sesijskog tokena, koji se šalje u `Authorization: Bearer` headeru prema backendu, kako bi svaki zahtjev bio vezan uz konkretnog korisnika i njegovu ulogu.
- Podaci o korisnicima (demo računi) pohranjeni su u modelu, a lozinke se uspoređuju korištenjem algoritma za hashiranje (bcrypt), čime se izbjegava pohrana lozinki u čistom tekstu i djelomično adresira problem Authentication Failures.
- Uveden je osnovni mehanizam zaštite od brute force napada na login (brojanje neuspjelih pokušaja i blokada prijave uz poruku i odbrojavanje na frontend-u).
- Backend koristi SQLite bazu podataka za medicinske zapise, a sav pristup bazi ide preko parametriziranih upita, čime se izbjegava SQL injection i demonstrira pravilna obrana od Injection ranjivosti.
- Za zdravstvene zapise implementiran je jednostavan model “vlasništva nad zapisom” na razini uloga i korisnika:
    - liječnik (`doctor`) vidi sve zapise i može ih dodavati, uređivati i brisati,
    - svaki pacijent (`patient1`, `patient2`) vidi samo svoj zapis.
- Na backend je dodan `helmet` middleware radi postavljanja sigurnosnih HTTP headera (CSP, X-Frame-Options, X-Content-Type-Options, itd.), što je preporučena mjera protiv Security Misconfiguration.
- CORS je namjerno ograničen na `http://localhost:3000` kao jedini dopušteni origin za browser, umjesto korištenja `*`, čime se smanjuje površina napada kroz pogrešnu konfiguraciju.
- U dokumentaciji (.md datoteke) opisano je kako bi se u produkcijskom okruženju rješavale Cryptographic Failures (HTTPS/TLS, enkripcija osjetljivih podataka, siguran key management), iako zbog edukativne naravi projekta ta enkripcija nije u potpunosti implementirana.

Cilj je pokazati kako se sigurnosni zahtjevi i kontrole integriraju u projekt od samog početka, umjesto da se sigurnost dodaje naknadno.

## Faze SDLC procesa u projektu

U projektu će se koristiti pojednostavljeni, ali jasan sigurni SDLC koji obuhvaća sljedeće faze:

### 1. Faza – Zahtjevi i analiza (Requirements)

U ovoj fazi bit će:

- definirani funkcionalni zahtjevi aplikacije (prijava, prikaz medicinskih zapisa, uloge liječnik/pacijent, dodavanje i uređivanje zapisa);
- identificirani sigurnosni zahtjevi specifični za zdravstvene podatke: povjerljivost, integritet, ograničenje pristupa, auditabilnost;
- mapirane relevantne OWASP Top 10 kategorije koje su prioritet za projekt (Broken Access Control, Authentication Failures, Security Misconfiguration, Injection, Cryptographic Failures);
- izrađen osnovni model prijetnji (threat model) za ključne funkcionalnosti (login, pristup zapisima, manipulacija zapisima).

Svrha faze je osigurati da su sigurnosne potrebe (posebno za zdravstvene podatke) jasno definirane prije početka dizajna i implementacije.

### 2. Faza – Sigurni dizajn (Secure Design)

U ovoj fazi bit će:

- dizajnirana arhitektura aplikacije s odvojenim frontendom i backend API-jem, uz ograničeni CORS i jasne putanje `/api/login` i `/api/records`;
- definirane uloge i pravila pristupa (RBAC): tko smije vidjeti koje podatke i što smije raditi (doctor vs patient);
- osmišljen način pohrane i pristupa medicinskim zapisima (SQLite + parametrizirani upiti), kako bi se od početka izbjegao SQL injection;
- planirane sigurnosne kontrole kao što su: autentikacija, autorizacija, validacija inputa, sigurni HTTP headeri, ograničavanje pokušaja prijave, odvajanje konfiguracije (CORS, portovi) od koda;
- definirano kako će se sigurnosne postavke odraziti u svim okolinama (dev/demo naspram produkcije) – npr. različiti credentiali, TLS, enkripcija podataka.

Cilj je izbjeći Insecure Design time što se sigurnost promišlja na razini arhitekture i tokova, a ne samo na razini pojedinačnih funkcija.

### 3. Faza – Implementacija (Secure Implementation)

U ovoj fazi bit će:

- implementiran backend u Node.js/Express s odvojenim modulima za rute, modele, middleware i bazu;
- dodan login endpoint koji provodi autentikaciju, provjeru hashiranih lozinki i kreiranje sesijskog tokena;
- implementiran `authMiddleware` koji provjerava token iz `Authorization` headera i popunjava `req.user`, te `requireRole` za provjeru uloge;
- implementirane rute za medicinske zapise (`GET/POST/PUT/DELETE /api/records`) koje koriste RBAC i parametrizirane SQL upite prema SQLite bazi;
- dodan `helmet` i pravilno konfiguriran CORS na backendu, kako bi se smanjile Security Misconfiguration ranjivosti;
- implementirana osnovna zaštita od brute force napada na login: brojanje neuspjelih pokušaja i privremena blokada prijave s prikazom odbrojavanja na frontend-u;
- izrađen React frontend koji koristi token za sve zaštićene zahtjeve i vizualno razlikuje mogućnosti doktora i pacijenta (npr. prikaz forme za dodavanje/uređivanje samo za doktora).

Naglasak je na implementaciji kontrola proizašlih iz prve dvije faze, umjesto ad-hoc rješavanja bugova.

### 4. Faza – Testiranje (Security Testing)

U ovoj fazi bit će:

- ručno testirani glavni sigurnosni scenariji:
    - neautentificirani korisnik ne može vidjeti niti mijenjati medicinske zapise;
    - korisnici u ulozi `patient` vide samo svoje zapise;
    - liječnik može dodavati, uređivati i brisati zapise;
    - pokušaji pristupa zaštićenim rutama bez tokena ili s krivim tokenom završavaju s odgovarajućim HTTP statusima;
- testirani scenariji neispravne prijave: pogrešno korisničko ime/lozinka, više uzastopnih neuspjelih pokušaja s aktiviranjem blokade i ispravnim odbrojavanjem;
- provjereno da parametrizirani upiti ispravno tretiraju “čudan” input kao podatak, a ne izvršivi SQL kod;
- pokrenuti osnovni SAST alati (npr. Semgrep lokalno ili kroz CI) nad backend/frontendom, kako bi se pronašli potencijalni sigurnosni problemi u kodu.

Cilj je potvrditi da implementirane kontrole doista rade i da najčešći sigurnosni antipatterni (SQLi, otvoreni endpointi, neograničen login) nisu prisutni.

### 5. Faza – Deploy i konfiguracija (Deployment \& Security Configuration)

U ovoj fazi bit će:

- dokumentirano kako bi se aplikacija postavila u produkcijsko okruženje uz sigurnu konfiguraciju:
    - korištenje HTTPS/TLS za sav promet prema API-ju,
    - korištenje različitih credentiala i konfiguracija po okruženjima (development, test, produkcija),
    - pravilno podešavanje CORS-a, sigurnosnih HTTP headera, logiranja i error handlinga;
- opisano kako bi se frontend i backend hostali (npr. odvojeni serveri/servisi) i kako bi se primijenili principi najmanjih privilegija na razini infrastrukture;
- definirano da demo korisnici, lozinke i konfiguracija nisu prihvatljivi za produkciju te kako bi se u pravom sustavu koristila baza korisnika, hashirane lozinke, key management i enkripcija podataka.

Iako se projekt primarno izvodi lokalno kao demo, ovdje se jasno opisuje kako bi isti koncepti bili primijenjeni “u stvarnom svijetu”.

### 6. Faza – Održavanje i poboljšanja (Maintenance \& Continuous Improvement)

U ovoj fazi bit će:

- predloženo praćenje logova i sigurnosnih događaja (pokušaji prijave, neautorizirani pristupi) kao dio operativne sigurnosti;
- predviđeno redovito ažuriranje biblioteka i okvira (Express, React, SQLite, bcrypt, helmet) radi zakrpa sigurnosnih ranjivosti;
- dokumentirano kako bi se nakon sigurnosnih incidenata (npr. sumnje na kompromitirane credove) provela analiza i poboljšale kontrole (npr. jača autentikacija, dodatne validacije, dodatne mjere enkripcije);
- predložen nastavak korištenja i integracije SAST/DAST alata kroz CI/CD pipeline kako bi se nove ranjivosti pronašle prije produkcije.

Na ovaj način projekt služi kao konkretan primjer kako se sigurnost integrira u sve faze SDLC-a za web-aplikaciju koja obrađuje osjetljive (zdravstvene) podatke, uz referencu na OWASP Top 10 rizike koje je projekt pokušao adresirati.

