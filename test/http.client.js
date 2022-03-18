const http = require("http");
const https = require("https");

module.exports = function httpRequest(url, options, body, cb) {
  var proto = url.indexOf("http:") === 0 ? http : https;
  //console.log("request opt", options);
  const request = proto.request(url, options, (response) => {
    if (response.statusCode >= 400) {
      request.destroy(new Error());
      return cb(new Error("Non success status code"), response, null);
    }
    //console.log(response.statusCode);

    const chunks = [];
    response.on("data", (chunk) => {
      chunks.push(chunk);
    });

    response.once("end", () => {
      const buffer = Buffer.concat(chunks);
      return cb(null, response, buffer.toString());
    });

    response.once("error", (err) => {
      return cb(err, response, null);
    });
  });

  request.once("error", (err) => {
    return cb(err, null, null);
  });
  if (body) {
    request.setHeader("content-type", "application/json; charset=utf-8");
    request.write(JSON.stringify(body));
  }
  request.end();
};
