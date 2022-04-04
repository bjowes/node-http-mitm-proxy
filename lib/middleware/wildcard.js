'use strict';

/**
 * group1: subdomain
 * group2: domain.ext
 * exclude short domains (length < 4) to avoid catching double extensions (ex: net.au, co.uk, ...)
 */
const HOSTNAME_REGEX = /^(.+)(\.[^\.]{4,}(\.[^\.]{1,3})*\.[^\.]+)$/;

module.exports = {
  onCertificateRequired: function (hostname, callback) {
    var rootHost = hostname;
    if (HOSTNAME_REGEX.test(hostname)) {
      rootHost = hostname.replace(/^[^\.]+\./, '');
    }
    // Replace wildcards and colons, not portably supported in filenames
    const hostCertFilename = rootHost.replace(/\*/g, '_').replace(/\:/g, ';') + ext;
    return callback(null, {
      keyFile: this.sslCaDir + '/keys/_.' + hostCertFilename + '.key',
      certFile: this.sslCaDir + '/certs/_.' + hostCertFilename + '.pem',
      hosts: ['*.' + rootHost, rootHost],
    });
  },
};
