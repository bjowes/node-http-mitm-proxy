const net = require('net');
const tls = require('tls');
const http = require('http');
const https = require('https');
const events = require('events');

const debug = require('debug')('http-mitm-proxy:tunnelagent');

let agentCount = 0;

class SocketStore {
  sockets = {};

  insert(key, socket) {
    if (this.sockets[key]) {
      this.sockets[key].push(socket);
    } else {
      this.sockets[key] = [socket];
    }
  }

  get(key) {
    if (this.sockets[key] && this.sockets[key].length > 0) {
      return this.sockets[key].pop();
    }
    return undefined;
  }

  length(key) {
    if (this.sockets[key]) {
      return this.sockets[key].length;
    }
    return 0;
  }

  count() {
    let sum = 0;
    for (const property in this.sockets) {
      if (this.sockets.hasOwnProperty(property)) {
        sum += this.sockets[property].length;
      }
    }
    return sum;
  }

  remove(key, socket) {
    const socketIndex = this.sockets[key].indexOf(socket);
    if (socketIndex === -1) {
      throw new Error('SocketStore: Attempt to remove non-existing socket');
    }
    this.sockets[key].splice(socketIndex, 1);
  }

  replace(key, socket, newSocket) {
    this.sockets[key][this.sockets[key].indexOf(socket)] = newSocket;
  }

  destroy() {
    for (const property in this.sockets) {
      if (this.sockets.hasOwnProperty(property)) {
        const sockets = this.sockets[property];
        sockets.forEach((socket) => {
          socket.destroy();
        });
      }
    }
  }
}

module.exports = class TunnelAgent extends events.EventEmitter {
  request;
  options;
  defaultPort;
  maxSockets;
  requests;
  sockets;
  freeSockets;
  keepAlive;
  proxyOptions;
  destroyPending = false;
  agentId;
  createSocket;

  debugLog(message) {
    debug('[' + this.agentId + ']: ' + message);
  }

  constructor(options, proxyOverHttps = false, targetUsesHttps = false) {
    super();
    const self = this;
    this.options = options;
    this.proxyOptions = options.proxy || {};
    this.maxSockets = options.maxSockets || 1;
    this.keepAlive = options.keepAlive || false;
    this.requests = [];
    this.sockets = new SocketStore();
    this.freeSockets = new SocketStore();
    this.request = proxyOverHttps ? https.request : http.request;
    this.createSocket = targetUsesHttps ? this.createSecureSocket : this.createTcpSocket;
    this.defaultPort = targetUsesHttps ? 443 : 80;
    this.agentId = agentCount++;

    // attempt to negotiate http/1.1 for proxy servers that support http/2
    if (this.proxyOptions.secureProxy && !('ALPNProtocols' in this.proxyOptions)) {
      this.proxyOptions.ALPNProtocols = ['http 1.1'];
    }

    self.on('free', function onFree(socket, request) {
      for (let i = 0, len = self.requests.length; i < len; ++i) {
        const pending = self.requests[i];
        if (pending.socketKey === request.socketKey) {
          self.debugLog('socket free, reusing for pending request');
          // Detect the request to connect same origin server, reuse the connection.
          self.requests.splice(i, 1);
          pending.clientReq.reusedSocket = true;
          pending.clientReq.onSocket(socket);
          return;
        }
      }

      self.sockets.remove(request.socketKey, socket);
      if (!self.keepAlive) {
        socket.destroy();
        self.debugLog('socket free, non keep-alive => destroy socket');
      } else {
        // save the socket for reuse later
        socket.removeAllListeners();
        socket.unref();
        self.freeSockets.insert(request.socketKey, socket);
        socket.once('close', (_) => {
          if (self.destroyPending) return;
          self.debugLog('remove socket on socket close');
          self.freeSockets.remove(request.socketKey, socket);
        });
      }
      self.processPending();
    });
  }

  /**
   * Counts all sockets active in requests and pending (keep-alive)
   *
   * @returns {number} The number of sockets, free and in use
   */
  socketCount() {
    return this.sockets.count() + this.freeSockets.count();
  }

  addRequest(req, _opts) {
    const self = this;
    const request = {
      clientReq: req,
      socketKey: `${_opts.host}:${_opts.port}`,
      options: { ..._opts, ...self.options },
    };

    if (self.sockets.length(request.socketKey) >= this.maxSockets) {
      // We are over limit for the host so we'll add it to the queue.
      self.requests.push(request);
      return;
    }

    if (self.keepAlive) {
      const socket = self.freeSockets.get(request.socketKey);
      if (socket) {
        this.debugLog('addRequest: reuse free socket for ' + request.socketKey);
        socket.removeAllListeners();
        socket.ref();
        self.sockets.insert(request.socketKey, socket);
        req.reusedSocket = true;
        self.executeRequest(request, socket);
        return;
      }
    }

    // If we are under maxSockets create a new one.
    self.createSocket(request);
  }

  executeRequest(request, socket) {
    const self = this;
    socket.on('free', onFree);
    socket.on('close', onCloseOrRemove);
    socket.on('agentRemove', onCloseOrRemove);
    request.clientReq.onSocket(socket);

    function onFree() {
      self.debugLog('onFree');
      self.emit('free', socket, request);
    }

    function onCloseOrRemove(hadError) {
      self.debugLog('onClose');
      if (self.destroyPending) return;
      socket.removeListener('free', onFree);
      socket.removeListener('close', onCloseOrRemove);
      socket.removeListener('agentRemove', onCloseOrRemove);
      if (self.keepAlive) {
        socket.emit('close', hadError); // Let the freeSocket event handler remove the socket
      }
      self.processPending();
    }
  }

  escapeHost(hostname, port) {
    if (hostname.indexOf(':') === -1) {
      return `${hostname}:${port}`;
    }
    return `[${hostname}]:${port}`;
  }

  createSocketInternal(request, cb) {
    const self = this;
    const host = this.escapeHost(request.options.host, request.options.port);
    const connectOptions = {
      ...self.proxyOptions,
      method: 'CONNECT',
      path: host,
      headers: {
        host: host,
      },
    };
    if (request.options.localAddress) {
      connectOptions.localAddress = request.options.localAddress;
    }
    if (self.proxyOptions.proxyAuth) {
      connectOptions.headers = connectOptions.headers || {};
      connectOptions.headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(self.proxyOptions.proxyAuth).toString('base64');
    }

    const connectReq = self.request(connectOptions);
    connectReq.once('connect', onConnect);
    connectReq.once('error', onError);
    connectReq.end();

    function onConnect(res, socket, head) {
      connectReq.removeAllListeners();
      socket.removeAllListeners();

      if (res.statusCode !== 200) {
        self.debugLog('tunneling socket could not be established, statusCode=' + res.statusCode);
        socket.destroy();
        request.clientReq.destroy(new Error('tunneling socket could not be established, ' + 'statusCode=' + res.statusCode));
        self.processPending();
        return;
      }
      if (head.length > 0) {
        self.debugLog('got illegal response body from proxy');
        socket.destroy();
        request.clientReq.destroy(new Error('got illegal response body from proxy'));
        self.processPending();
        return;
      }
      self.debugLog('tunneling connection established');
      self.sockets.insert(request.socketKey, socket);
      return cb(socket);
    }

    function onError(cause) {
      connectReq.removeAllListeners();
      self.debugLog('tunneling socket could not be established, cause=' + cause.message + '\n' + cause.stack);
      request.clientReq.destroy(new Error('tunneling socket could not be established, ' + 'cause=' + cause.message));
      self.processPending();
    }
  }

  processPending() {
    const pending = this.requests.shift();
    if (pending) {
      // If we have pending requests and a socket gets closed a new one
      // needs to be created to take over in the pool for the one that closed.
      this.createSocket(pending);
    }
  }

  createTcpSocket(request) {
    const self = this;
    self.createSocketInternal(request, (socket) => self.executeRequest(request, socket));
  }

  createSecureSocket(request) {
    const self = this;
    self.createSocketInternal(request, function (socket) {
      const hostHeader = request.clientReq.getHeader('host');
      const tlsOptions = {
        ...omit(self.options, 'host', 'path', 'port'),
        socket: socket,
      };
      let servername = '';
      if (hostHeader) {
        servername = new URL('https://' + hostHeader).hostname;
      } else if (request.options.host) {
        servername = request.options.host;
      }
      if (servername) {
        tlsOptions.servername = servername;
      }

      const secureSocket = tls.connect(0, tlsOptions);
      self.sockets.replace(request.socketKey, socket, secureSocket);
      self.executeRequest(request, secureSocket);
    });
  }

  destroy() {
    this.debugLog('destroying agent');
    this.destroyPending = true;
    this.sockets.destroy();
    this.freeSockets.destroy();
  }
};

function omit(obj, ...keys) {
  const ret = {};
  for (var key in obj) {
    if (!keys.includes(key)) {
      ret[key] = obj[key];
    }
  }
  return ret;
}
