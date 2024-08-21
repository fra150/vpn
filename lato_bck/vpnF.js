const VPNServer = require('./vpn2');
const vpnLogger = require('./vpn');


//Da modificare secondo il proprio scopo. 
const vpnOptions = {
  port: 1194,
  serverIP: '10.8.0.1',
  ipRange: ['10.8.0.2', '10.8.0.254'],
  dns: ['8.8.8.8', '8.8.4.4'],
  routes: [{ destination: '0.0.0.0/0', gateway: '10.8.0.1' }],
  logger: vpnLogger, 
};

const vpnServer = new VPNServer(vpnOptions);
vpnServer.start().catch((error) => {
  vpnLogger.error('Failed to start VPN server', error);
});
