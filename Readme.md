# Documentazione del Server VPN

Questo repository contiene il codice sorgente di un server VPN implementato in Node.js. Il server fornisce crittografia, decrittografia e obfuscazione dei dati, oltre alla gestione dei gruppi utente e al controllo delle autorizzazioni. Include anche una funzione di inoltro TCP per inviare dati a un server remoto.

## Indice

- [Installazione](#installazione)
- [Utilizzo](#utilizzo)
- [Endpoint API](#endpoint-api)
- [Funzioni](#funzioni)
- [Crittografia e Decrittografia](#crittografia-e-decrittografia)
- [Inoltro TCP](#inoltro-tcp)
- [Operazioni sul Database](#operazioni-sul-database)
- [Gestione degli Errori e Registrazione](#gestione-degli-errori-e-registrazione)
- [Misure di Sicurezza](#misure-di-sicurezza)
- [Rotazione delle Chiavi](#rotazione-delle-chiavi)
- [Arresto Controllato](#arresto-controllato)
- [Contributi](#contributi)
- [Organizzazione del Codice](#organizzazione-del-codice)
  - [`Vpn.js`](#vpnjs)
  - [`Vpn2.js`](#vpn2js)
  - [`VpnF.js`](#vpnfjs)
- [Convenzioni di Denominazione](#convenzioni-di-denominazione)
- [Interazioni tra i File](#interazioni-tra-i-file)

## Installazione

1. Clona il repository:

```bash
git clone https://github.com/fra150/vpn.git
```

2. Installa le dipendenze:

```bash
cd vpn-server
npm install
```

3. Crea un file `.env` nella directory principale e aggiungi le seguenti variabili d'ambiente:

```
DB_HOST=your_database_host
DB_USER=your_database_user
DB_PASSWORD=your_database_password
DB_NAME=your_database_name
```

4. Genera i certificati SSL per HTTPS:

```bash
mkdir ssl
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout ssl/server.key -out ssl/server.crt
```

## Utilizzo

Per avviare il server VPN, esegui:

```bash
npm start
```

Il server ascolterà sulla porta 443 per le connessioni HTTPS e sulla porta 8080 per le connessioni VPN.

## Endpoint API

- `POST /api/groups`: Crea un nuovo gruppo utente.
- `POST /api/groups/addUser`: Aggiunge un utente a un gruppo.
- `GET /api/checkPermission`: Verifica se un utente ha l'autorizzazione per una risorsa.

## Funzioni

- `createUserGroup(groupName)`: Crea un nuovo gruppo utente nel database.
- `addUserToGroup(userId, groupId)`: Aggiunge un utente a un gruppo nel database.
- `checkUserPermission(userId, resourceId)`: Verifica se un utente ha l'autorizzazione per una risorsa nel database.
- `generateEncryptionKey()`: Genera una chiave di crittografia casuale.
- `encrypt(data, key)`: Crittografa i dati utilizzando AES-256-GCM.
- `decrypt(data, key)`: Decrittografa i dati utilizzando AES-256-GCM.
- `obfuscateData(data, key)`: Obfusca i dati utilizzando un'operazione XOR semplice.
- `forwardToInternet(data)`: Inoltra i dati a un server remoto utilizzando TCP.
- `handleClientData(data, socket, clientEncryptionKey)`: Gestisce i dati ricevuti da un client.
- `initializeVPNServer()`: Inizializza il server VPN e gestisce le connessioni in entrata.
- `rotateEncryptionKeys()`: Ruota le chiavi di crittografia per tutti gli utenti attivi nel database.
- `gracefulShutdown()`: Arresta il server in modo controllato e chiude le connessioni.
- `getUserGroups(userId)`: Ottiene i gruppi a cui appartiene un utente dal database con la memorizzazione nella cache.

## Crittografia e Decrittografia

Il server utilizza AES-256-GCM per la crittografia e la decrittografia dei dati. Le funzioni `encrypt` e `decrypt` gestiscono il processo di crittografia e decrittografia.

## Inoltro TCP

La funzione `forwardToInternet` invia dati a un server remoto utilizzando TCP. Crea un nuovo socket TCP, si connette al server remoto e scrive i dati sul socket.

## Operazioni sul Database

Il server utilizza la libreria `mysql2/promise` per interagire con un database MySQL. L'oggetto `dbConfig` contiene i dettagli della connessione al database. Le seguenti operazioni sul database sono supportate:

- Creazione di un nuovo gruppo utente.
- Aggiunta di un utente a un gruppo.
- Verifica se un utente ha l'autorizzazione per una risorsa.
- Rotazione delle chiavi di crittografia per tutti gli utenti attivi.

## Gestione degli Errori e Registrazione

Il server utilizza la libreria `winston` per la registrazione. Registra informazioni, errori e avvisi sulla console e sui file di registro (`error.log` e `combined.log`).

## Misure di Sicurezza

Il server implementa le seguenti misure di sicurezza:

- Utilizza HTTPS per la comunicazione sicura.
- Utilizza il middleware Helmet per impostare intestazioni HTTP relative alla sicurezza.
- Implementa il rate limiting per prevenire l'abuso.
- Utilizza una chiave di crittografia casuale per ogni connessione client.
- Obfusca i dati prima di inoltrarli al server remoto.

## Rotazione delle Chiavi

Il server ruota le chiavi di crittografia per tutti gli utenti attivi ogni 24 ore. La funzione `rotateEncryptionKeys` gestisce il processo di rotazione delle chiavi.

## Arresto Controllato

Il server supporta l'arresto controllato. Quando il server riceve un segnale SIGTERM o SIGINT, chiude il server HTTP e tutte le connessioni aperte. Se il server non si chiude entro 10 secondi, si arresta forzatamente.

## Contributi

I contributi sono benvenuti! Se trovi problemi o hai suggerimenti per miglioramenti, apri un problema o invia una richiesta pull.

## Organizzazione del Codice

ale codice non segue le line guida "best practice " ma è organizzato in tre file principali: `Vpn.js`, `Vpn2.js`, e `VpnF.js`. Ciascuno di questi file ha un ruolo specifico nel funzionamento del server VPN.

### `Vpn.js`

Questo file contiene la configurazione del logger, la configurazione del middleware di sicurezza, la configurazione del rate limiting, e le funzioni di crittografia e decrittografia. Inoltre, gestisce le connessioni TCP e le operazioni sul database per la gestione dei gruppi utente e delle autorizzazioni.

### `Vpn2.js`

Questo file definisce la classe `VPNServer`, che gestisce l'intera funzionalità del server VPN. La classe include metodi per avviare il server, gestire le connessioni dei client, elaborare i pacchetti, assegnare indirizzi IP, configurare il firewall, e generare la configurazione per i client.

### `VpnF.js`

Questo file crea un'istanza della classe `VPNServer` con le opzioni specificate e avvia il server. In caso di errore durante l'avvio del server, registra l'errore e termina il processo.

## Convenzioni di Denominazione

I nomi dei file sono stati scelti per riflettere il loro contenuto e ruolo nel progetto. Ad esempio, `Vpn.js` contiene funzionalità generiche e di supporto, `Vpn2.js` definisce la classe principale del server VPN, e `VpnF.js` è il file di avvio del server.

## Interazioni tra i File

- `Vpn.js` esporta funzioni e oggetti utilizzati da `Vpn2.js` per la gestione delle connessioni, della crittografia, e delle operazioni sul database.
- `Vpn2.js` utilizza la classe `VPNServer` per gestire il server VPN.
- `VpnF.js` importa la classe `VPNServer` da `Vpn2.js` e crea un'istanza del server con le opzioni specificate.

Questa organizzazione del codice migliora la modularità e la manutenibilità, rendendo più facile aggiungere nuove funzionalità, correggere bug, e comprendere il flusso di lavoro del server VPN.
