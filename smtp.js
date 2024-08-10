const crypto = require('crypto');
const net = require('net');
const { authenticate } = require('mailauth');

const DEBUG = true; // Debug flag

const log = (...args) => {
  if (DEBUG) {
    console.log(...args);
  }
};

const findRemitLines = (emailContent) => {
  const lines = emailContent.split('\n');
  const start = lines.findIndex(line => !line.includes(':')) + 1;
  const regex = /^REMIT\s+(\d+(?:\.\d+)?)\s+([A-Z]{3})(?:\/([r][A-Za-z0-9]{23,34}))?\s*$/gm;
  const matches = [];

  for (let i = start; i < lines.length; ++i) {
    const match = regex.exec(lines[i]);
    if (match !== null) {
      matches.push({
        fullMatch: match[0],
        amount: parseFloat(match[1]),
        currency: match[2],
        issuer: match[3] || null
      });
    }
  }

  return matches;
};

const extractHeaders = (emailContent) => {
  const headers = {};
  const lines = emailContent.split('\r\n');
  
  for (const line of lines) {
    if (line === '') break;
    const [key, value] = line.split(': ');
    if (key && value) {
      headers[key.toLowerCase()] = value;
    }
  }

  return headers;
};

const canonicalizeAndHashEmail = (email) => {
  const canonicalEmail = canonicalizeEmail(email).toLowerCase();
  const innerHash = 'EEEEFFFF' + crypto.createHash('sha512').update(canonicalEmail).digest('hex');
  return crypto.createHash('sha512')
    .update(Buffer.from(innerHash, 'hex'))
    .digest('hex')
    .toUpperCase()
    .slice(0, 40);
};

const canonicalizeEmail = (email) => {
  const [localPart, domain] = email.split('@');
  return `${canonicalizeLocalPart(localPart, domain)}@${canonicalizeDomain(domain)}`;
};

const canonicalizeLocalPart = (localPart, domain) => {
  let part = localPart.replace(/\([^()]*\)/g, '').replace(/\s/g, '');
  const plusIndex = part.indexOf('+');
  if (plusIndex !== -1) {
    part = part.slice(0, plusIndex);
  }
  part = part.replace(/\.+$/, '');
  
  if (domain.toLowerCase() === 'gmail.com') {
    part = part.replace(/\./g, '');
  }
  
  return part;
};

const canonicalizeDomain = (domain) => domain.toLowerCase().replace(/\.+$/, '');

const extractEmailAddress = (headerValue) => {
  const match = headerValue.match(/<([^>]+)>/);
  return match ? match[1] : headerValue.trim();
};

const processRemit = (from, currency, amount, issuer, to) => {
  const fromHash = canonicalizeAndHashEmail(from);
  const toHash = canonicalizeAndHashEmail(to);
  log(`PROCESS REMIT: ${from} [${fromHash}] => (${amount} ${currency}) => ${to} [${toHash}]`);

  if (fromHash === toHash) {
    log("Self remit, ignoring.");
  }
};

const fs = require('fs')
const processEmail = async (content) => {
    fs.writeFileSync('email.in', content, 'utf-8');
  try {
    const remits = findRemitLines(content);
    const headers = extractHeaders(content);

    if (remits.length === 0 || !headers['to'] || !headers['from']) return;

    const from = headers['from'];
    const to = headers['to'];

    log('Remits found:', remits);
    log('From:', from);
    log('To:', to);

    const authResult = await authenticate(content, {});
    log('Authentication result:', authResult);
    log('DKIM results:', authResult.dkim.results);

    if (authResult.dkim.results[0].info.slice(0, 9) === 'dkim=pass') {
      log("DKIM PASSED");
      remits.forEach(remit => 
        processRemit(
          extractEmailAddress(from),
          remit.currency,
          remit.amount,
          remit.issuer,
          extractEmailAddress(to)
        )
      );
    }
  } catch (error) {
    console.error('Error processing email:', error);
  }
};

const createSMTPServer = () => {
  const handleCommand = (command, socket, state) => {
    const [cmd, ...args] = command.split(' ');

    switch (cmd) {
      case 'HELO':
      case 'EHLO':
        socket.write('250-SMTP Server\r\n250 SMTPUTF8\r\n');
        break;
      case 'MAIL':
        state.mailFrom = args.join(' ').split(':')[1];
        socket.write('250 OK\r\n');
        break;
      case 'RCPT':
        state.rcptTo = args.join(' ').split(':')[1];
        socket.write('250 OK\r\n');
        break;
      case 'DATA':
        state.dataMode = true;
        socket.write('354 Start mail input; end with <CRLF>.<CRLF>\r\n');
        break;
      case 'QUIT':
        socket.write('221 Bye\r\n');
        socket.end();
        break;
      case 'RSET':
        Object.assign(state, { mailFrom: '', rcptTo: '', dataMode: false, emailContent: '' });
        socket.write('250 OK\r\n');
        break;
      case 'NOOP':
        socket.write('250 OK\r\n');
        break;
      case 'VRFY':
        socket.write('252 Cannot VRFY user, but will accept message and attempt delivery\r\n');
        break;
      case 'EMESSAGE':
        socket.write('250 OK: EMESSAGE command accepted\r\n');
        break;
      default:
        socket.write('500 Command not recognized\r\n');
    }
  };

  return net.createServer((socket) => {
    log('Client connected');
    socket.write('220 Simple SMTP Server\r\n');

    const state = { mailFrom: '', rcptTo: '', dataMode: false, emailContent: '' };

    socket.on('data', (data) => {
      const input = data.toString();

      if (state.dataMode) {
        state.emailContent += input;
        if (state.emailContent.endsWith('\r\n.\r\n')) {
          processEmail(state.emailContent.slice(0, -3));
          socket.write('250 OK: Message accepted for delivery\r\n');
          Object.assign(state, { mailFrom: '', rcptTo: '', dataMode: false, emailContent: '' });
        }
      } else {
        handleCommand(input.trim().toUpperCase(), socket, state);
      }
    });

    socket.on('end', () => {
      log('Client disconnected');
    });

    socket.on('error', (error) => {
      console.error('Socket error:', error);
    });
  });
};

const PORT = 25;
const server = createSMTPServer();

server.listen(PORT, () => {
  console.log(`SMTP Server running on port ${PORT}`);
});

server.on('error', (error) => {
  console.error('Server error:', error);
});
