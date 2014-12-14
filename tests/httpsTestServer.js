
var static = require('node-static'),
    http = require('http'),
    https = require('https'),
    fs = require('fs'),
    config = {
      contentDir: './tests/',
      tlsDir: './tests/'
    };

http.createServer(function(req, res) {
  var domain = req.headers.host;
  req.on('end', function() {
    res.writeHead(302, {
      Location: 'https://'+domain+'/'+req.url.substring(1),
        'Access-Control-Allow-Origin': '*'
      });
    res.end('Location: https://'+domain+'/'+req.url.substring(1));
  });
}).listen(80);

var file = new(static.Server)(config.contentDir, {
  headers: {
    'Access-Control-Allow-Origin': '*'
  }
});

https.createServer({
  key: fs.readFileSync(config.tlsDir+'/server.key'),
  cert: fs.readFileSync(config.tlsDir+'/server.crt')
}, function(req, res) {
  file.serve(req, res);
}).listen(443);
