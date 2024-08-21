// Importa i moduli necessari
const net = require('net');
const crypto = require('crypto');
const dns = require('dns');
const { execSync } = require('child_process');
const winston = require('winston');
const openvpnmanager = require('node-openvpn');

// Configurazione dell'istanza OpenVPN
const opts = {
  host: '127.0.0.1', // Normalmente '127.0.0.1'
  port: 1337, // Porta della console di gestione OpenVPN
  timeout: 1500, // Timeout per la connessione
  logpath: 'log.txt', // Scrive l'output della console di OpenVPN in un file
};

const auth = {
  user: 'vpnUserName',
  pass: 'vpnPassword',
};

// Connetti alla gestione OpenVPN
const openvpn = openvpnmanager.connect(opts);

// Gestisci gli eventi della console di OpenVPN
openvpn.on('connected', () => {
  openvpnmanager.authorize(auth);
  console.log('Connesso alla console di gestione OpenVPN');
});

openvpn.on('console-output', (output) => {
  console.log('Output della console di OpenVPN:', output);
});

openvpn.on('state-change', (state) => {
  console.log('Cambiamento di stato di OpenVPN:', state);
});

openvpn.on('error', (error) => {
  console.error('Errore di OpenVPN:', error);
});

// Disconnetti quando necessario
openvpn.on('disconnected', () => {
  openvpnmanager.destroy();
  console.log('Disconnesso dalla console di gestione OpenVPN');
});

// Classe per gestire il server VPN
class VPNServer {
  constructor(options) {
    this.options = options;
    this.clients = new Map();
    this.ipPool = new Set(options.ipRange);
    this.server = null;
    this.logger =
      options.logger ||
      winston.createLogger({ level: 'info', transports: [new winston.transports.Console()] });
  }

  // Avvia il server VPN
  async start() {
    try {
      // Configura il firewall
      this.configureFirewall();

      // Crea il server VPN
      this.server = net.createServer(this.handleConnection.bind(this));
      this.server.listen(this.options.port, () => {
        this.logger.info(`Server VPN in ascolto sulla porta ${this.options.port}`);
      });
    } catch (error) {
      this.logger.error('Impossibile avviare il server VPN:', error);
      this.cleanup();
    }
  }

  // Gestisci una nuova connessione
  handleConnection(socket) {
    const clientId = `${socket.remoteAddress}:${socket.remotePort}`;
    this.logger.info(`Nuova connessione client: ${clientId}`);

    const clientIP = this.assignIP();
    if (!clientIP) {
      this.logger.error('Nessun indirizzo IP disponibile');
      socket.end();
      return;
    }

    const client = {
      socket,
      ip: clientIP,
      encryptionKey: crypto.randomBytes(32),
    };

    this.clients.set(clientId, client);

    socket.on('data', (data) => this.handleClientData(clientId, data));
    socket.on('close', () => this.handleClientDisconnect(clientId));
    socket.on('error', (error) => this.handleClientError(clientId, error));

    // Invia configurazione al client
    const config = this.generateClientConfig(client);
    socket.write(JSON.stringify(config));
  }

  // Gestisci i dati ricevuti da un client
  handleClientData(clientId, data) {
    const client = this.clients.get(clientId);
    if (!client) return;

    try {
      // Decrittografa i dati
      const decrypted = this.decrypt(data, client.encryptionKey);

      // Processa i pacchetti
      this.processPacket(decrypted, client);
    } catch (error) {
      this.logger.error(`Impossibile gestire i dati del client ${clientId}:`, error);
    }
  }

  // Gestisci i dati ricevuti dall'interfaccia tun
  handleTunData(data) {
    // Implementazione semplificata: Non usiamo `node-tuntap`, quindi potresti voler gestire questo tramite OpenVPN
    this.logger.info('Gestione dei dati tun:', data);
  }

  // Processa un pacchetto
  processPacket(packet, client) {
    try {
      // Log the packet and client for debugging purposes
      this.logger.debug(`Elaborazione del pacchetto per il client ${client.ip}:`, packet);

      // Log a success message
      this.logger.info(`Pacchetto elaborato con successo per il client ${client.ip}`);
    } catch (error) {
      // Log the error message and the error object
      this.logger.error(
        `Errore durante l'elaborazione del pacchetto per il client ${client.ip}:`,
        error,
      );

      // Optionally, you can re-throw the error to propagate it to the caller
      throw error;
    }
  }

  // Assegna un indirizzo IP a un client
  assignIP() {
    for (const ip of this.ipPool) {
      if (!this.isIPAssigned(ip)) {
        this.ipPool.delete(ip);
        return ip;
      }
    }
    return null;
  }

  // Verifica se un indirizzo IP è assegnato a un client
  isIPAssigned(ip) {
    for (const client of this.clients.values()) {
      if (client.ip === ip) return true;
    }
    return false;
  }

  // Trova un client per indirizzo IP
  findClientByIP(ip) {
    for (const client of this.clients.values()) {
      if (client.ip === ip) return client;
    }
    return null;
  }

  // Gestisci la disconnessione di un client
  handleClientDisconnect(clientId) {
    const client = this.clients.get(clientId);
    if (client) {
      this.ipPool.add(client.ip);
      this.clients.delete(clientId);
      this.logger.info(`Client disconnesso: ${clientId}`);
    }
  }

  // Gestisci un errore di un client
  handleClientError(clientId, error) {
    this.logger.error(`Errore con il client ${clientId}: ${error.message}`);
    this.handleClientDisconnect(clientId);
  }

  // Configura il firewall
  configureFirewall() {
    try {
      execSync('iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE');
      execSync('iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT');
      execSync('iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT');
      this.logger.info('Firewall configurato con successo');
    } catch (error) {
      this.logger.error('Impossibile configurare il firewall', error);
    }
  }

  // Genera la configurazione per un client
  generateClientConfig(client) {
    return {
      ip: client.ip,
      dns: this.options.dns,
      routes: this.options.routes,
    };
  }

  // Crittografa i dati
  encrypt(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, encrypted, tag]);
  }

  // Decrittografa i dati
  decrypt(data, key) {
    const iv = data.slice(0, 16);
    const tag = data.slice(-16);
    const encrypted = data.slice(16, -16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }

  // Risolve un nome di dominio in un indirizzo IP
  async resolveDNS(domain) {
    return new Promise((resolve, reject) => {
      dns.resolve4(domain, (err, addresses) => {
        if (err) reject(err);
        else resolve(addresses[0]);
      });
    });
  }

  // Pulisce le risorse
  cleanup() {
    if (this.server) {
      this.server.close(() => {
        this.logger.info('Server VPN chiuso');
      });
    }

    this.clients.forEach((client) => {
      client.socket.destroy();
    });

    this.logger.info('Tutte le risorse sono state pulite');
  }
}

// Esporta la classe VPNServer
module.exports = VPNServer;
