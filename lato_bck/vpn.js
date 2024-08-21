const express = require('express');
const https = require('https');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const axios = require('axios');
require('dotenv').config();
const mysql = require('mysql2/promise');
const { performance, PerformanceObserver } = require('perf_hooks');
const NodeCache = require('node-cache');
const cache = new NodeCache();

const app = express();

// Configurazione del logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'vpn-service' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console(), // Aggiunto il trasporto console
  ],
});

// Middleware di sicurezza
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
});
app.use(limiter);

// Configurazione della connessione al database
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};

async function createUserGroup(groupName) {
  const connection = await mysql.createConnection(dbConfig);
  try {
    await connection.execute('INSERT INTO user_groups (name) VALUES (?)', [groupName]);
    logger.info(`Created new user group: ${groupName}`);
  } catch (error) {
    logger.error('Error creating user group', { error: error.message });
    throw error;
  } finally {
    await connection.end();
  }
}

async function addUserToGroup(userId, groupId) {
  const connection = await mysql.createConnection(dbConfig);
  try {
    await connection.execute(
      'INSERT INTO user_group_memberships (user_id, group_id) VALUES (?, ?)',
      [userId, groupId],
    );
    logger.info(`Added user ${userId} to group ${groupId}`);
  } catch (error) {
    logger.error('Error adding user to group', { error: error.message });
    throw error;
  } finally {
    await connection.end();
  }
}

async function getUserGroups(userId) {
  const cacheKey = `userGroups:${userId}`;
  const cachedData = cache.get(cacheKey);

  if (cachedData) {
    return cachedData;
  }

  const connection = await mysql.createConnection(dbConfig);
  try {
    const [groups] = await connection.execute(
      `
      SELECT g.* FROM user_groups g
      JOIN user_group_memberships ugm ON g.id = ugm.group_id
      WHERE ugm.user_id = ?
    `,
      [userId],
    );

    cache.set(cacheKey, groups, 60); // Memorizza i risultati in cache per 60 secondi

    return groups;
  } catch (error) {
    logger.error('Error getting user groups', { error: error.message });
    throw error;
  } finally {
    await connection.end();
  }
}

async function checkUserPermission(userId, resourceId) {
  const connection = await mysql.createConnection(dbConfig);
  try {
    const [permissions] = await connection.execute(
      `
      SELECT p.* FROM permissions p
      JOIN user_group_memberships ugm ON p.group_id = ugm.group_id
      WHERE ugm.user_id = ? AND p.resource_id = ?
    `,
      [userId, resourceId],
    );
    return permissions.length > 0;
  } catch (error) {
    logger.error('Error checking user permission', { error: error.message });
    throw error;
  } finally {
    await connection.end();
  }
}

// API per la gestione dei gruppi e delle autorizzazioni
app.post('/api/groups', async (req, res) => {
  try {
    const { groupName } = req.body;
    if (!groupName) {
      return res.status(400).json({ error: 'Group name is required' });
    }
    await createUserGroup(groupName);
    res.status(201).json({ message: 'Group created successfully' });
  } catch (error) {
    logger.error('Error creating group', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/groups/addUser', async (req, res) => {
  try {
    const { userId, groupId } = req.body;
    if (!userId || !groupId) {
      return res.status(400).json({ error: 'User ID and Group ID are required' });
    }
    await addUserToGroup(userId, groupId);
    res.status(200).json({ message: 'User added to group successfully' });
  } catch (error) {
    logger.error('Error adding user to group', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/checkPermission', async (req, res) => {
  try {
    const { userId, resourceId } = req.query;
    if (!userId || !resourceId) {
      return res.status(400).json({ error: 'User ID and Resource ID are required' });
    }
    const hasPermission = await checkUserPermission(userId, resourceId);
    res.json({ hasPermission });
  } catch (error) {
    logger.error('Error checking permission', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Funzioni di crittografia e decrittografia
function generateEncryptionKey() {
  return crypto.randomBytes(32);
}

function encrypt(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + encrypted + tag.toString('hex');
}

function decrypt(data, key) {
  const iv = Buffer.from(data.slice(0, 32), 'hex');
  const encryptedData = data.slice(32, -32);
  const tag = Buffer.from(data.slice(-32), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function obfuscateData(data, key) {
  const obfuscated = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    obfuscated[i] = data[i] ^ key[i % key.length];
  }
  return obfuscated;
}

// Implementazione dell'invio a un server remoto tramite TCP
function forwardToInternet(data) {
  const client = new net.Socket();
  client.connect(80, 'www.example.com', () => {
    client.write(data);
  });

  client.on('data', (data) => {
    logger.info('Data received from server:', data.toString());
  });

  client.on('error', (error) => {
    logger.error('Error connecting to server:', error.message);
  });

  client.on('close', () => {
    logger.info('Connection to remote server closed');
  });
}

function handleClientData(data, socket, clientEncryptionKey) {
  const encryptedData = encrypt(data, clientEncryptionKey);
  const obfuscatedData = obfuscateData(Buffer.from(encryptedData, 'hex'), generateEncryptionKey());
  forwardToInternet(obfuscatedData);
}

function initializeVPNServer() {
  const clients = new Map();

  function handleConnection(socket) {
    const clientEncryptionKey = generateEncryptionKey();
    clients.set(socket, { key: clientEncryptionKey });

    socket.on('data', (data) => {
      try {
        const decryptedData = decrypt(data.toString('hex'), clientEncryptionKey);
        handleClientData(decryptedData, socket, clientEncryptionKey);
      } catch (error) {
        logger.error('Error decrypting data', { error: error.message });
        socket.destroy();
      }
    });

    socket.on('close', () => {
      clients.delete(socket);
    });

    socket.on('error', (error) => {
      logger.error('Socket error', { error: error.message });
      socket.destroy();
    });
  }

  const vpnServer = net.createServer(handleConnection);

  vpnServer.listen(8080, () => {
    logger.info('VPN server listening on port 8080');
  });

  vpnServer.on('error', (error) => {
    logger.error('VPN server error', { error: error.message });
  });
}

// Esegui la rotazione delle chiavi ogni 24 ore

async function rotateEncryptionKeys() {
  const connection = await mysql.createConnection(dbConfig);

  try {
    logger.info('Starting encryption key rotation');

    // Ottieni tutti gli utenti attivi
    const [users] = await connection.execute(
      'SELECT id, username, password, encryption_key FROM vpn_users WHERE is_active = true',
    );

    for (const user of users) {
      // Genera una nuova chiave di crittografia
      const newEncryptionKey = crypto.randomBytes(32).toString('hex');

      // Decifra la password attuale con la vecchia chiave
      const currentPassword = decrypt(user.password, user.encryption_key);

      // Cifra la password con la nuova chiave
      const newEncryptedPassword = encrypt(currentPassword, newEncryptionKey);

      // Aggiorna il database con la nuova chiave e la password ricifratta
      await connection.execute(
        'UPDATE vpn_users SET password = ?, encryption_key = ? WHERE id = ?',
        [newEncryptedPassword, newEncryptionKey, user.id],
      );

      logger.info(`Rotated encryption key for user: ${user.username}`);
    }

    logger.info('Encryption key rotation completed successfully');
  } catch (error) {
    logger.error('Error during encryption key rotation', { error: error.message });
  } finally {
    await connection.end();
  }
}

// Funzioni di supporto per la crittografia e la decrittografia
function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text, key) {
  const parts = text.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Esegui la rotazione delle chiavi ogni 24 ore
setInterval(rotateEncryptionKeys, 24 * 60 * 60 * 1000);

// Funzione per chiudere correttamente il server e le connessioni
function gracefulShutdown() {
  logger.info('Shutting down gracefully...');
  server.close(() => {
    logger.info('HTTP server closed');
    // Chiudi qui eventuali altre connessioni o risorse
    process.exit(0);
  });

  // Se il server non si chiude entro 10 secondi, forza la chiusura
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

initializeVPNServer();

async function main() {
  const connection = await mysql.createConnection(dbConfig);

  try {
    const [tables] = await connection.execute('SHOW TABLES');
    logger.info('Connected to database. Tables:', tables);
  } catch (error) {
    logger.error('Error connecting to database', { error: error.message });
    process.exit(1);
  } finally {
    await connection.end();
  }

  // Avvia il server HTTPS
  const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, 'ssl', 'server.key')),
    cert: fs.readFileSync(path.join(__dirname, 'ssl', 'server.crt')),
  };

  const server = https.createServer(sslOptions, app);

  server.listen(443, () => {
    logger.info('HTTPS Server running on port 443');
  });
}

main().catch((error) => {
  logger.error('Error in main function', { error: error.message });
  process.exit(1);
});

module.exports = {
  createUserGroup,
  addUserToGroup,
  checkUserPermission,
  generateEncryptionKey,
  encrypt,
  decrypt,
  obfuscateData,
  forwardToInternet,
  handleClientData,
  initializeVPNServer,
  rotateEncryptionKeys,
  gracefulShutdown,
  getUserGroups,
};
