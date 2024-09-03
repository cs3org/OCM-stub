const https = require('https');
const fs = require('fs');
const url = require('url');
const fetch = require('node-fetch');
const util = require('util');
// const exec = util.promisify(require('child_process').exec);
const crypto = require('crypto');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
    }
});
const TLS_DIR = '../tls';

const SERVER_NAME = process.env.HOST || 'server';
const SERVER_HOST = process.env.SERVER_HOST || `${SERVER_NAME}.docker`;
const SERVER_ROOT = `https://${SERVER_HOST}`;
const USER = `einstein`;
const PROVIDER_ID = SERVER_HOST;
const MESH_PROVIDER = SERVER_HOST;

// const HTTPS_OPTIONS = {
//   key: fs.readFileSync(`/etc/letsencrypt/live/${SERVER_HOST}/privkey.pem`),
//   cert: fs.readFileSync(`/etc/letsencrypt/live/${SERVER_HOST}/cert.pem`),
//   ca: fs.readFileSync(`/etc/letsencrypt/live/${SERVER_HOST}/chain.pem`)
// }
const HTTPS_OPTIONS = {
  key: fs.readFileSync(`${TLS_DIR}/${SERVER_NAME}.key`),
  cert: fs.readFileSync(`${TLS_DIR}/${SERVER_NAME}.crt`)
}

const grants = {
  'localhost': {
    '123456': 'asdfgh'
  }
}

function sendHTML(res, text) {
  res.end(`<!DOCTYPE html><html><head></head><body>${text}</body></html>`);
}

// singleton global, naively assume only one share exists at a time:
let mostRecentShareIn = {};

async function sign(message) {
  const data = Buffer.from(message);
  const signature = await crypto.sign('RSA-SHA256', data, privateKey).toString('base64');
  console.log('signed', signature);
  return signature;
}

async function check(message, signature) {
  console.log('SENDER VERIFY', message, signature, publicKey);
  const data = Buffer.from(message);
  const verify = await crypto.verify('RSA-SHA256', data, publicKey, Buffer.from(signature, 'base64'));
  console.log('verify done', verify);
  return verify;
}

async function verify(message, signature, fqdn) {
  const senderConfig = await getServerConfigForServer(fqdn);
  const senderPubKey = senderConfig.config.publicKey;
  console.log('fetched sender pub key', senderConfig, senderPubKey);
  console.log('RECIPIENT VERIFY', message, signature, senderPubKey);
  const data = Buffer.from(message);
  const verify = await crypto.verify('RSA-SHA256', data, senderPubKey, Buffer.from(signature, 'base64'));
  console.log('verify done', verify);
  return verify;
}

async function getServerFqdnForUser(otherUser) {
  console.log('getServerFqdnForUser', otherUser);

  let otherServer = otherUser.split('@').splice(1).join('@').replace('\/', '/');
  console.log(otherServer);
  if (otherServer.startsWith('http://')) {
    otherServer = otherServer.substring('http://'.length);
  } else if (otherServer.startsWith('https://')) {
    otherServer = otherServer.substring('http://'.length);
  }
  if (otherServer.endsWith('/')) {
    otherServer = otherServer.substring(0, otherServer.length - 1);
  }
  return otherServer;
}
async function getServerConfigForServer(fqdn) {
  console.log('fetching', `https://${fqdn}/ocm-provider/`);
  const configResult = await fetch(`https://${fqdn}/ocm-provider/`);
// const text = await configResult.text();
// console.log({ text });
// JSON.parse(text);
  return { config: await configResult.json(), fqdn };
}
async function getServerConfigForUser(otherUser) {
  const fqdn = await getServerFqdnForUser(otherUser);
  return getServerConfigForServer(fqdn);
}

async function notifyProvider(obj, notif) {
  console.log('notifyProvider', obj, notif);
  // FIXME: reva sets no `sharedBy` and no `sender`
  // and sets `owner` to a user opaqueId only (e.g. obj.owner: '4c510ada-c86b-4815-8820-42cdf82c3d51').
  // what we ultimately need when a share comes from reva is obj.meshProvider, e.g.: 'revad1.docker'.
  const { config } = await getServerConfigForUser(obj.sharedBy || obj.sender || /* obj.owner || */ `${obj.owner}@${obj.meshProvider}`);
  if (config.endPoint.substr(-1) == '/') {
    config.endPoint = config.endPoint.substring(0, config.endPoint.length - 1);
  }

  const postRes = await fetch(`${config.endPoint}/notifications`, {
    method: 'POST',
    body: JSON.stringify(notif)
  });
  console.log('notification sent!', postRes.status, await postRes.text());
}

async function forwardInvite(invite) {
  console.log('forwardInvite', invite);
  const { config, fqdn } = await getServerConfigForUser(invite);
  console.log('discovered', config, fqdn);
  if (!config.endPoint) {
    config.endPoint = process.env.FORCE_ENDPOINT;
  }

  const inviteSpec = {
    invite: {
      token: invite.split('@')[0],
      userId: 'marie',
      recipientProvider: 'stub2.docker',
      name: 'Marie Curie',
      email: 'marie@cesnet.cz',
    }
  }
  let endPoint = config.endPoint || config.endpoint;
  if (endPoint.substr(-1) == '/') {
    endPoint = endPoint.substring(0, endPoint.length - 1);
  }
  console.log('posting', `${endPoint}/invites/accept`, JSON.stringify(inviteSpec, null, 2))
  const postRes = await fetch(`${endPoint}/invites/accept`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(inviteSpec, null, 2),
  });
  console.log('invite forwarded', postRes.status, await postRes.text());
}
function getDigest(body) {
  return 'SHA-256=' + crypto.createHash('sha256').update(body).digest('base64');
}
async function generateSignatureHeaders(body, endPoint, target) {
  const urlObj = new URL(endPoint);
  const digest = getDigest(body);
  const headers = {
    'request-target': target,
    'content-length': body.length.toString(),
    host: urlObj.host,
    date: new Date().toUTCString(),
    digest
  };
  const message = Object.values(headers).join('\n');
  const signed = await sign(message);
  const checked = await check(message, signed);
  console.log({ checked });
  headers.signature = [
    `keyId="${SERVER_HOST}"`,
    `algorithm="rsa-sha256"`,
    `headers="${Object.keys(headers)}"`,
    `signature="${signed}"`
  ].join(',');
  return headers;
}

async function createShare(consumer) {
  console.log('createShare', consumer);
  // config={
  //   endPoint: 'https://example.com/'
  // };
  const { config, fqdn } = await getServerConfigForUser(consumer);
  // console.log(config);
  if (!config.endPoint) {
    config.endPoint = process.env.FORCE_ENDPOINT;
  }

  const shareSpec = {
    shareWith: consumer,
    name: 'Test share from stub',
    providerId: PROVIDER_ID,
    meshProvider: MESH_PROVIDER,
    owner: `${USER}@${SERVER_HOST}`,
    ownerDisplayName: USER,
    sharedBy: `${USER}@${SERVER_HOST}`,
    senderDisplayName: USER,
    shareType: 'user',
    resourceType: 'file',
    protocol: {
      name: 'webdav',
      options: {
        code: '123456',
        sharedSecret: 'shareMeNot'
      },
      webdav: {
        code: '123456',
        sharedSecret: 'shareMeNot'
      }
    }
  }
  console.log(shareSpec, shareSpec.protocol);
  if (config.endPoint.endsWith('/')) {
    config.endPoint = config.endPoint.substring(0, config.endPoint.length - 1);
  }

  
  const body = JSON.stringify(shareSpec, null, 2);
  const headers = await generateSignatureHeaders(body, config.endPoint, 'post /shares');
  headers['content-type'] = 'application/json';
  
  console.log('signature headers generated', headers);

  const postRes = await fetch(`${config.endPoint}/shares`, {
    method: 'POST',
    headers,
    body,
  });
  console.log('outgoing share created!', postRes.status, await postRes.text());
  return fqdn;
} 
function expectHeader(headers, name, expected) {
  if (headers[name] === expected) {
    console.log(`header ${name} OK`, expected);
  } else {
    console.log(`header ${name} missing or wrong`, JSON.stringify(headers), expected);
  }
}
function checkExpectedHeaders(received, expected, onesToCheck) {
  onesToCheck.forEach(name => expectHeader(received, name, expected[name]));
}
async function fetchAccessToken(tokenEndpoint, code) {
  const body = JSON.stringify({
    grant_type: `ocm_authorization_code`,
    code,
    client_id: SERVER_HOST,
  }, null, 2);
  const headers = await generateSignatureHeaders(body, tokenEndpoint, 'post /token');
  headers['content-type'] = 'application/json';
  const tokenResult = await fetch(tokenEndpoint, {
    method: 'POST',
    body,
    headers
  });
  const response = await tokenResult.json();
  console.log('got token response', response);
  return response;
}

async function checkSignature(bodyIn, headersIn, target) {
  console.log('checking signature');
  const digest = getDigest(bodyIn);
  const headers = {
    'request-target': target,
    'content-length': bodyIn.length.toString(),
    host: SERVER_HOST,
    date: headersIn.date,
    digest
  };
  const message = Object.values(headers).join('\n');
  console.log(message);
  checkExpectedHeaders(headersIn, headers, ['request-target', 'content-length', 'host', 'digest']);
  //                    1                   2                  3                    4
  const rx = /^keyId=\"(.*)\"\,algorithm=\"(.*)\"\,headers\=\"(.*)\",signature\=\"(.*)\"$/g;
  const parsed = rx.exec(headersIn.signature);
  console.log(parsed);
  const fqdn = parsed[1];
  const signature = parsed[4];
  const verified = await verify(message, signature, fqdn);
  console.log({ verified, fqdn });
  if (verified) {
    return fqdn;
  }
}

const server = https.createServer(HTTPS_OPTIONS, async (req, res) => {
  console.log(req.method, req.url, req.headers);
  let bodyIn = '';
  req.on('data', (chunk) => {
    console.log('CHUNK', chunk.toString());
    bodyIn += chunk.toString();
  });
  req.on('end', async () => {
    try {
      if (req.url === '/token') {
        const signingServer = await checkSignature(bodyIn, req.headers, 'post /token');
        console.log('token request', bodyIn, signingServer);
        let params;
        try {
          params = JSON.parse(bodyIn);
        } catch (e) {
          res.writeHead(400);
          sendHTML(res, 'Cannot parse JSON');
          return;
        }
        if (typeof grants[params.client_id] !== 'object') {
          res.writeHead(403);
          sendHTML(res, `no grants found for client ${client_id}`);
          return;
        }
        if (typeof grants[params.client_id][params.code] !== 'string') {
          res.writeHead(403);
          sendHTML(res, `grant ${params.code} not found for client ${client_id}`);
          return;
        }
        const token = grants[params.code];
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({
          access_token: grants[params.client_id][params.code],
          token_type: 'bearer',
          expires_in: 3600,
          refresh_token: 'qwertyuiop',
        }));
      } else if (req.url === '/webdav/file.txt') {
        console.log('API access', req.headers['authorization']);
        if (req.headers['authorization'] === `Bearer asdfgh`) {
          res.end('The content of the file, well done!');
        } else if (typeof req.headers['authorization'] === 'string') {
          res.writeHead(403);
          res.end('No access, sorry');
        } else {
          res.writeHead(401);
          res.end('Please use a short-lived bearer for this API. You can exchange the code from the share at the token endpoint using httpsig');
        }
    } else if (req.url === '/ocm-provider/') {
        console.log('yes /ocm-provider/');
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({
          enabled: true,
          apiVersion: '1.0-proposal1',
          endPoint: `${SERVER_ROOT}/ocm`,
          tokenEndpoint: `${SERVER_ROOT}/token`,
          resourceTypes: [
            {
              name: 'file',
              shareTypes: [ 'user', 'group' ],
              protocols: { webdav: '/webdav/' }
            }
          ],
          publicKey
        }));
      } else if (req.url === '/ocm/shares') {
        console.log('yes /ocm/shares');
        try {
          mostRecentShareIn = JSON.parse(bodyIn);
        } catch (e) {
          res.writeHead(400);
          sendHTML(res, 'Cannot parse JSON');
          return;
        }
        if (typeof req.headers['signature'] === 'string') {
          const signingServer = await checkSignature(bodyIn, req.headers, 'post /shares');
          const claimedServer = await getServerFqdnForUser(mostRecentShareIn.sharedBy);
          if (signingServer !== claimedServer) {
            console.log('ALARM! Claimed server does not match signing server', claimedServer, signingServer);
          }
          if (mostRecentShareIn?.protocol?.webdav?.code) {
            console.log('code received! exchanging it for token...', mostRecentShareIn?.protocol?.webdav?.code);
            const { config, fqdn } = await getServerConfigForServer(claimedServer);
            console.log('token endpoint discovered', config.tokenEndpoint);
            const token = await fetchAccessToken(config.tokenEndpoint, mostRecentShareIn?.protocol?.webdav?.code);
            console.log('will now use token to access webdav', token);
            const result = await fetch('https://localhost/webdav/file.txt', {
              headers: {
                authorization: `Bearer ${token.access_token}`
              }
            });
            console.log('API accessed', result.status, await result.text());
          }
        } else {
          console.log('unsigned request to create share');
        }

        // {
        //   shareWith: "admin@https:\/\/stub1.pdsinterop.net",
        //   shareType: "user",
        //   name: "Reasons to use Nextcloud.pdf",
        //   resourceType: "file",
        //   description:"",
        //   providerId:202,
        //   owner: "alice@https:\/\/nc1.pdsinterop.net\/",
        //   ownerDisplayName: "alice",
        //   sharedBy: "alice@https:\/\/nc1.pdsinterop.net\/",
        //   sharedByDisplayName":"alice",
        //   "protocol":{
        //     "name":"webdav",
        //     "options":{
        //       "sharedSecret":"lvns5N9ZXm1T1zx",
        //       "permissions":"{http:\/\/open-cloud-mesh.org\/ns}share-permissions"
        //     }
        //   }
        // }
        // obj.id = obj.providerId;
        res.writeHead(201, {
          'Content-Type': 'application/json'
        });
        res.end(JSON.stringify({
          "recipientDisplayName": "Marie Curie"
        }, null, 2));
      } else if (req.url.startsWith('/publicLink')) {
        console.log('yes publicLink');
        const urlObj = new URL(req.url, SERVER_ROOT);
        if (urlObj.search.startsWith('?saveTo=')) {
          console.log('creating share', urlObj.search);
          const otherServerRoot = await createShare(decodeURIComponent(urlObj.search).substring('?saveTo='.length));
          res.writeHead(301, {
            location: otherServerRoot
          });
          sendHTML(res, `Redirecting you to ${otherServerRoot}`);
        } else {
          sendHTML(res, 'yes publicLink, saveTo?');
        }
      } else if (req.url.startsWith('/forwardInvite')) {
        console.log('yes forwardInvite');
        const urlObj = new URL(req.url, SERVER_ROOT);
        await forwardInvite(decodeURIComponent(urlObj.search).substring('?'.length));
        sendHTML(res, 'yes forwardInvite');
      } else if (req.url.startsWith('/shareWith')) {
        console.log('yes shareWith');
        const urlObj = new URL(req.url, SERVER_ROOT);
        await createShare(decodeURIComponent(urlObj.search).substring('?'.length));
        sendHTML(res, 'yes shareWith');
      } else if (req.url.startsWith('/acceptShare')) {
        console.log('yes acceptShare');
        try {
          console.log('Creating notif to accept share, obj =', mostRecentShareIn);
          const notif = {
            type: 'SHARE_ACCEPTED',
            resourceType: mostRecentShareIn.resourceType,
            providerId: mostRecentShareIn.providerId,
            notification: {
              sharedSecret: (
                mostRecentShareIn.protocol ?
                (
                  mostRecentShareIn.protocol.options ?
                  mostRecentShareIn.protocol.options.sharedSecret :
                  undefined
                ) :
                undefined
              ),
              message: 'Recipient accepted the share'
            }
          };
          notifyProvider(mostRecentShareIn, notif);
        } catch (e) {
          console.error(e);
          sendHTML(res, `no acceptShare - fail`);
        }
        sendHTML(res, 'yes acceptShare');
      } else if (req.url.startsWith('/deleteAcceptedShare')) {
        console.log('yes deleteAcceptedShare');
        const notif = {
          type: 'SHARE_DECLINED',
          message: 'I don\'t want to use this share anymore.',
          id: mostRecentShareIn.id,
          createdAt: new Date()
        };
        // When unshared from the provider side:
        // {
        //   "notificationType":"SHARE_UNSHARED",
        //   "resourceType":"file",
        //   "providerId":"89",
        //   "notification":{
        //     "sharedSecret":"N7epqXHRKXWbg8f",
        //     "message":"File was unshared"
        //   }
        // }
        console.log('deleting share', mostRecentShareIn);
        try {
          notifyProvider(mostRecentShareIn, notif);
        } catch (e) {
          sendHTML(res, `no deleteAcceptedShare - fail ${provider}ocm-provider/`);
        }
        sendHTML(res, 'yes deleteAcceptedShare');
      } else if (req.url.startsWith('/?')) {
        console.log('yes /', mostRecentShareIn);
        if (req.url.indexOf('session=active') != -1) {
          sendHTML(res, `<form method="get">
            <input type="submit" value="Log out">
          </form> /` + JSON.stringify(mostRecentShareIn, null, 2));
        } else {
          sendHTML(res, `<form method="get">
            <input type="hidden" name="session" value="active">
            <input type="submit" value="Log in">
          </form> /` + JSON.stringify(mostRecentShareIn, null, 2));
        }
      } else if (req.url.startsWith('/meshdir?')) {

    const queryObject = url.parse(req.url, true).query;
    console.log(queryObject);
        const config = {
          nextcloud1: "https://nextcloud1.docker/index.php/apps/sciencemesh/accept",
          owncloud1: "https://owncloud1.docker/index.php/apps/sciencemesh/accept",
          nextcloud2: "https://nextcloud2.docker/index.php/apps/sciencemesh/accept",
          owncloud2: "https://owncloud2.docker/index.php/apps/sciencemesh/accept",
          stub2: "https://stub.docker/ocm/invites/forward",
          revad2: undefined
        };
        const items = [];
        const scriptLines = [];
        Object.keys(config).forEach(key => {
          if (typeof config[key] === "string") {
            items.push(`  <li><a id="${key}">${key}</a></li>`);
            scriptLines.push(`  document.getElementById("${key}").setAttribute("href", "${config[key]}"+window.location.search);`);
          } else {
            const params = new URLSearchParams(req.url.split('?')[1]);
		  console.log(params);
            const token = params.get('token');
            const providerDomain = params.get('providerDomain');
            items.push(`  <li>${key}: Please run <tt>ocm-invite-forward -idp ${providerDomain} -token ${token}</tt> in Reva's CLI tool.</li>`);
          }
        })

        console.log('meshdir', mostRecentShareIn);
        sendHTML(res, `Welcome to the meshdir stub. Please click a server to continue to:\n<ul>${items.join('\n')}</ul>\n<script>\n${scriptLines.join('\n')}\n</script>\n`);
      } else {
        console.log('not recognized');
        sendHTML(res, `OK ${req.url}`);
      }
    } catch (e) {
      console.error(e);
    }
  });
});
server.listen(443);
console.log(`Browse to https://localhost or https://${SERVER_HOST}`);