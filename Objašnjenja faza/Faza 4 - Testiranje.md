# Testiranje

## Uvod

Sigurnosno testiranje predstavlja jednu od najvažnijih faza unutar sigurnog SDLC procesa jer omogućuje identifikaciju i uklanjanje ranjivosti prije nego aplikacija bude puštena u produkcijsko okruženje. Iako se sigurnost razmatra već u fazama planiranja, dizajna i razvoja, tek se kroz testiranje može provjeriti kako se aplikacija ponaša u stvarnim uvjetima rada. Integracijom sigurnosnog testiranja u SDLC smanjuje se rizik od zlouporabe sustava, povećava se povjerenje korisnika te se osigurava dugoročna stabilnost i sigurnost aplikacije.

U kontekstu ovog projekta, faza testiranja bila je usmjerena na dinamičko testiranje sigurnosti aplikacije (DAST), koje analizira aplikaciju tijekom njezina izvođenja, bez uvida u izvorni kod. Ovakav pristup omogućuje simulaciju stvarnih napada iz perspektive vanjskog napadača te otkrivanje ranjivosti koje se često ne mogu uočiti statičkom analizom. DAST predstavlja važan element sigurnog SDLC-a jer pruža realnu procjenu sigurnosnog stanja aplikacije neposredno prije faze implementacije.

Za provođenje sigurnosnog testiranja korišten je alat OWASP ZAP (Zed Attack Proxy), jedan od najčešće korištenih open-source alata za dinamičko testiranje web aplikacija. OWASP ZAP omogućuje automatizirano i ručno testiranje sigurnosti te se u praksi često koristi kao dio sigurnosnih provjera unutar SDLC procesa. Korištenjem ovog alata osigurana je primjena industrijski priznatih sigurnosnih metoda i usklađenost s OWASP smjernicama.

Tijekom testiranja proveden je pasivni sigurnosni scan, čiji je cilj bio prikupljanje informacija o aplikaciji i identifikacija potencijalnih sigurnosnih problema bez aktivnog slanja zlonamjernih zahtjeva. Pasivni scan omogućuje analizu sigurnosnih zaglavlja, konfiguracijskih pogrešaka i drugih indikatora ranjivosti, pri čemu ne utječe na normalno funkcioniranje aplikacije. Ova metoda posebno je korisna u ranim fazama testiranja unutar SDLC-a jer pruža početni uvid u sigurnosno stanje sustava uz minimalan rizik.

Nakon pasivnog skeniranja proveden je aktivni sigurnosni scan, koji uključuje slanje posebno oblikovanih zahtjeva aplikaciji s ciljem otkrivanja stvarnih ranjivosti, poput SQL injekcija, cross-site scripting (XSS) ranjivosti ili nepravilnog rukovanja greškama. Aktivni scan omogućio je dublju analizu sigurnosti aplikacije te provjeru učinkovitosti implementiranih sigurnosnih mehanizama. Ova faza testiranja ima ključnu ulogu u SDLC procesu jer omogućuje pravovremeno otkrivanje i ispravljanje kritičnih sigurnosnih problema.

Uz automatizirane mogućnosti alata OWASP ZAP, provedeno je i ručno sigurnosno testiranje, koje je omogućilo detaljniju analizu poslovne logike i specifičnih scenarija korištenja aplikacije. Ručno testiranje nadopunjuje automatizirane alate jer omogućuje prepoznavanje složenijih sigurnosnih problema koje alati često ne mogu detektirati. Kombinacijom DAST-a, pasivnog i aktivnog skeniranja te ručnog testiranja ostvaren je sveobuhvatan pristup sigurnosnom testiranju, čime se dodatno naglašava važnost integracije sigurnosti u sve faze SDLC procesa.

## Dinamičko testiranje sigurnosti aplikacije (DAST)

Dinamičko testiranje sigurnosti aplikacija (DAST) predstavlja metodu sigurnosne analize koja se provodi nad aplikacijom tijekom njezina izvođenja, s ciljem otkrivanja ranjivosti iz perspektive potencijalnog napadača. Za razliku od statičkih analiza, DAST ne zahtijeva uvid u izvorni kod, već analizira ponašanje aplikacije kroz mrežnu komunikaciju i odgovore na različite zahtjeve. U sklopu sigurnog SDLC procesa, DAST ima važnu ulogu jer omogućuje provjeru stvarne izloženosti aplikacije sigurnosnim prijetnjama prije njezine implementacije u produkciju.

U ovom projektu DAST analiza provedena je korištenjem alata OWASP ZAP, koji omogućuje automatizirano i ručno testiranje web aplikacija.Rezultati DAST analize prikazani su u sigurnosnom izvještaju koji je generirao OWASP ZAP, a koji sadrži popis identificiranih sigurnosnih upozorenja različitih razina rizika. Analizom izvještaja uočeno je postojanje više sigurnosnih slabosti koje bi u stvarnom okruženju mogle biti iskorištene od strane napadača. Iako nisu sve ranjivosti kritične, njihov ukupni broj i priroda ukazuju na potrebu dodatnog unaprjeđenja sigurnosnih kontrola unutar aplikacije. Među identificiranim rizicima nalaze se problemi vezani uz 
- sigurnosna zaglavlja
- upravljanje sesijama
- nedovoljno strogu validaciju korisničkog unosa

Ovakvi rizici mogu omogućiti napade poput cross-site scriptinga (XSS), neovlaštenog pristupa korisničkim podacima ili prikupljanja osjetljivih informacija o aplikaciji. Iako neki od ovih problema sami po sebi ne predstavljaju izravnu prijetnju, u kombinaciji s drugim ranjivostima mogu značajno povećati sigurnosni rizik sustava.

Značenje identificiranih rizika ogleda se u mogućem narušavanju povjerljivosti, integriteta i dostupnosti aplikacije. Neadekvatno postavljene sigurnosne postavke mogu napadaču olakšati prikupljanje informacija o sustavu ili izvođenje složenijih napada. Upravo zbog toga DAST analiza ima važnu ulogu u SDLC procesu jer omogućuje pravovremeno otkrivanje takvih problema prije no što aplikacija postane dostupna krajnjim korisnicima.

Smanjenje i uklanjanje identificiranih rizika moguće je primjenom preporuka navedenih u OWASP ZAP izvještaju, kao i slijedeći OWASP Top 10 smjernice. To uključuje pravilnu konfiguraciju sigurnosnih zaglavlja, poboljšanje validacije i sanitizacije korisničkog unosa, sigurnije upravljanje sesijama te redovito provođenje sigurnosnog testiranja. Integracijom ovih mjera u SDLC proces osigurava se viša razina sigurnosti aplikacije i smanjuje se rizik od budućih sigurnosnih incidenata.

### Active scan

Active scan predstavlja aktivnu tehniku sigurnosnog testiranja pri kojoj se aplikaciji namjerno šalju različiti neuobičajeni, nepostojeći ili zlonamjerno oblikovani zahtjevi s ciljem izazivanja neočekivanog ponašanja. Za razliku od pasivnog skeniranja, aktivno skeniranje izravno testira otpornost aplikacije na pokušaje napada, poput pristupa nepostojećim rutama, internim datotekama ili manipulacije parametrima zahtjeva. U sigurnom SDLC procesu, active scan ima važnu ulogu jer provjerava kako aplikacija reagira na stvarne pokušaje zlouporabe.

U ovom projektu active scan proveden je korištenjem alata OWASP ZAP, koji je automatski generirao velik broj HTTP zahtjeva prema aplikaciji. Testirani su različiti scenariji, uključujući pristup nepostojećim URL-ovima, pokušaje dohvaćanja internih konfiguracijskih i sistemskih datoteka (npr. .env, .git, WEB-INF, konfiguracijske XML datoteke), kao i slanje neuobičajenih parametara kroz GET i POST zahtjeve. Cilj ovih testova bio je provjeriti hoće li aplikacija neispravno obraditi zahtjeve ili izložiti osjetljive informacije.

Analizom odgovora aplikacije utvrđeno je da se HTTP status kod 200 OK vraća isključivo za legitimne i postojeće rute aplikacije. U slučajevima kada je OWASP ZAP slao zahtjeve prema nepostojećim ili nedozvoljenim resursima, aplikacija je ispravno vraćala odgovor 404 Not Found ili 400 Bad Request. Ovakvo ponašanje ukazuje na pravilnu implementaciju mehanizama za validaciju ruta i ulaznih parametara.

Posebno je važno istaknuti da aplikacija tijekom active scana nije pokazala znakove nestabilnosti, odnosno da nije došlo do rušenja aplikacije, promjene njezina ponašanja ili izvršavanja zlonamjernog inputa. Pokušaji pristupa internim datotekama, konfiguracijama i servisnim endpointima nisu rezultirali izlaganjem sadržaja, što upućuje na to da interni resursi nisu dostupni izvana. Time je potvrđeno da aplikacija ne izlaže osjetljive dijelove sustava koji bi mogli poslužiti kao ulazna točka za napadača.

Rezultati active scana ukazuju na nizak sigurnosni rizik vezan uz neovlašteni pristup resursima i neispravnu obradu HTTP zahtjeva. Ispravna validacija ruta, pravilno korištenje HTTP status kodova te nepostojanje izloženih internih datoteka značajno smanjuju mogućnost napada poput directory traversal, information disclosure ili neovlaštenog izvođenja koda. Ovi nalazi potvrđuju da su osnovne sigurnosne kontrole uspješno implementirane.

Unatoč pozitivnim rezultatima, preporučuje se nastaviti s redovitim provođenjem active scana kao dijela SDLC procesa, osobito nakon promjena u aplikaciji ili dodavanja novih funkcionalnosti. Time se osigurava da nova logika ne uvodi sigurnosne propuste te da aplikacija dugoročno zadržava visoku razinu otpornosti na napade.

### Passive scan

Pasivno skeniranje predstavlja proces u kojem se aplikacija promatra tijekom normalne uporabe, bez aktivnog slanja zlonamjernih ili manipuliranih zahtjeva. U tvom slučaju, OWASP ZAP je korišten kao proxy, što znači da je sav promet između klijenta i aplikacije prolazio kroz ZAP, gdje su se bilježili zahtjevi, odgovori poslužitelja i potencijalni sigurnosni problemi. Pasivno skeniranje analizira zaglavlja, kolačiće, konfiguracije i obrasce ponašanja aplikacije te identificira sigurnosne slabosti koje su vidljive bez agresivnog testiranja.

Ovakav pristup iznimno je važan za SDLC procese, posebno jer se može koristiti u ranim i srednjim fazama testiranja bez rizika od narušavanja funkcionalnosti aplikacije ili podataka. Pasivno skeniranje omogućuje kontinuiranu provjeru sigurnosnih postavki aplikacije tijekom razvoja i integracije. Time se sigurnosni problemi otkrivaju ranije, kada su troškovi njihovog ispravljanja manji nego u produkciji.

Iz pasivnog DAST izvještaja vidljivo je da je ZAP bilježio logove aktivnosti, odnosno koje su funkcionalnosti aplikacije testirane, kakvi su bili HTTP odgovori te postoje li potencijalna sigurnosna upozorenja. Posebna pažnja posvećena je HTTP kolačićima, pri čemu je provjereno imaju li postavljene sigurnosne zastavice poput HttpOnly, koje sprječavaju pristup kolačićima putem JavaScripta, te atribut SameSite postavljen na vrijednost Strict, čime se smanjuje rizik od CSRF napada. Također je analizirano koriste li se sigurni protokoli i enkripcija za prijenos osjetljivih podataka.

Rezultati skeniranja ukazuju da su određene dobre sigurnosne prakse već implementirane, poput korištenja sigurnih atributa kolačića i enkripcije osjetljivih informacija u prijenosu. Međutim, pasivno skeniranje može također generirati upozorenja nižeg ili srednjeg rizika, primjerice vezana uz nepotpuna sigurnosna zaglavlja, informativne poruke poslužitelja ili potencijalno preopširne HTTP odgovore. Takvi nalazi ne znače nužno da je aplikacija ranjiva, ali ukazuju na područja koja zahtijevaju dodatnu pažnju. Glavni rizici identificirani pasivnim skeniranjem odnose se na 
- mogućnost krađe sesije
- CSRF napade
- curenje informacija kroz zaglavlja
- neadekvatno postavljene sigurnosne politike

Ako, primjerice, kolačići nemaju pravilno postavljene zastavice ili se osjetljivi podaci prenose bez enkripcije, napadač bi mogao iskoristiti te slabosti bez potrebe za kompleksnim napadima. Upravo zato pasivno skeniranje služi kao prva linija obrane u otkrivanju osnovnih, ali čestih sigurnosnih propusta.

Kako bi se identificirani rizici minimizirali, preporučuje se dosljedna primjena sigurnih postavki kolačića (HttpOnly, Secure, SameSite), obavezno korištenje HTTPS-a, uklanjanje nepotrebnih informacija iz HTTP zaglavlja te redovito pokretanje pasivnih skenova tijekom razvoja. Uz to, rezultate pasivnog skeniranja treba kombinirati s aktivnim DAST testovima i ručnim sigurnosnim testiranjem kako bi se dobila cjelovita slika sigurnosti aplikacije unutar sigurnog SDLC procesa.

## Ručno testiranje

U sklopu faze testiranja sigurnosti, ručno sigurnosno testiranje ima ključnu ulogu jer omogućuje provjeru scenarija i logičkih grešaka koje automatizirani alati često ne mogu otkriti. Za razliku od pasivnog i aktivnog skeniranja, ručno testiranje se temelji na simulaciji ponašanja stvarnog napadača te analizi reakcija aplikacije u specifičnim situacijama. U SDLC kontekstu ono služi kao nadopuna automatiziranim testovima, posebno u fazama prije produkcije, kada je važno provjeriti poslovnu logiku i način na koji aplikacija obrađuje neuobičajene ili pogrešne korisničke radnje.

Jedan od ključnih aspekata ručnog testiranja bila je provjera mehanizma prijave i ponašanja aplikacije pri pogrešnoj autentifikaciji. Analizirane su poruke koje se prikazuju korisniku u slučaju neuspješne prijave kako bi se utvrdilo otkrivaju li previše informacija (npr. razlikovanje između pogrešnog korisničkog imena i lozinke). Takve poruke mogu napadaču olakšati pogađanje valjanih korisničkih računa. Sigurnosno ispravna praksa je korištenje generičkih poruka o grešci koje ne otkrivaju detalje o uzroku neuspjele prijave.

Daljnje ručno testiranje odnosilo se na pristup osjetljivim podacima i upravljanje ulogama korisnika. Provjeravano je razlikuje li se prikaz i dostupnost funkcionalnosti ovisno o ulozi korisnika (doktor naspram pacijenta) te postoji li mogućnost neovlaštenog pristupa podacima putem manipulacije URL-ova ili zahtjeva. Ovakvi testovi pomažu u otkrivanju propusta u kontroli pristupa (Broken Access Control), koji su među najčešćim i najkritičnijim ranjivostima prema OWASP-u.

Posebna pažnja posvećena je testiranju otpornosti aplikacije na SQL injection napade. Ručnim unosom zlonamjernih SQL izraza u obrasce za prijavu i pretraživanje provjeravano je koristi li aplikacija sigurne mehanizme za obradu unosa, poput parametarskih upita. Cilj ovog testiranja bio je utvrditi može li napadač manipulirati bazom podataka, zaobići autentifikaciju ili dobiti neovlašten pristup podacima. Ručno testiranje je ovdje posebno važno jer može otkriti ranjivosti koje nisu uvijek jasno vidljive u automatiziranim skenovima.

Na kraju, testiran je i scenarij brute force napada na mehanizam prijave. Simulirano je višestruko uzastopno unošenje pogrešnih korisničkih imena i lozinki kako bi se provjerilo postoje li zaštitni mehanizmi poput ograničenja broja pokušaja, vremenskog zaključavanja računa ili CAPTCHA provjera. Izostanak takvih zaštita predstavlja ozbiljan sigurnosni rizik jer omogućuje napadačima automatizirano pogađanje lozinki. Rezultati ovih testova naglašavaju važnost implementacije obrambenih mehanizama i kontinuiranog testiranja autentifikacijskih funkcionalnosti unutar sigurnog SDLC procesa.