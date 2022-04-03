const http = require('http');
const https = require('https');

module.exports = function httpRequest(url, options, body, cb) {
  var proto = url.indexOf('http:') === 0 ? http : https;
  const request = proto.request(url, options, (response) => {
    if (response.statusCode >= 400) {
      request.destroy(new Error());
      return cb(new Error('Non success status code'), response, null);
    }

    const chunks = [];
    response.on('data', (chunk) => {
      chunks.push(chunk);
    });

    response.once('end', () => {
      const buffer = Buffer.concat(chunks);
      return cb(null, response, buffer.toString());
    });

    response.once('error', (err) => {
      return cb(err, response, null);
    });
  });

  request.once('error', (err) => {
    return cb(err, null, null);
  });
  if (body) {
    const bodyStr = JSON.stringify(body);
    request.setHeader('content-type', 'application/json; charset=utf-8');
    request.setHeader('content-length', bodyStr.length);
    request.write(bodyStr);
  }
  request.end();
};
