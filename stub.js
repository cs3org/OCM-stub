const https = require("https");
const fs = require("fs");
const url = require("url");
const fetch = require("node-fetch");
const crypto = require("crypto");

// Import ocm-core for protocol logic
const core = require("./ocm-core");

const sharesSent = {};

// Invite-link state (using core's state factory)
const STUB_INVITE_TOKEN = "stub-invite-token-123456";
const inviteState = core.createInviteState(STUB_INVITE_TOKEN);
const acceptedInvites = inviteState.acceptedInvites;

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "pkcs1",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs1",
    format: "pem",
  },
});
const TLS_DIR = "../tls";

const SERVER_NAME = process.env.HOST || "server";
const SERVER_HOST = process.env.SERVER_HOST || `${SERVER_NAME}.docker`;
const SERVER_ROOT = `https://${SERVER_HOST}`;
const USER = `einstein`;
const PROVIDER_ID = SERVER_HOST;
const MESH_PROVIDER = SERVER_HOST;

// Local user info for invite responses
const LOCAL_USER = {
  userID: USER,
  email: `${USER}@${SERVER_HOST}`,
  name: "Albert Einstein",
};

// Use ocm-core for discovery
function getProviderDescriptor() {
  return core.getLocalDiscovery(SERVER_HOST, { publicKey });
}

const PROPFIND_RESPONSE = `\
<?xml version="1.0"?>\
<d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">\
  <d:response>\
    <d:href>/webdav-api/</d:href>\
     <d:propstat>\
      <d:prop>\
        <d:getlastmodified>Tue, 07 Jan 2025 08:26:30 GMT</d:getlastmodified>\
        <d:getcontentlength>164</d:getcontentlength>\
        <d:getcontenttype>text/plain</d:getcontenttype>\
        <oc:permissions>RGNVW</oc:permissions>\
        <d:resourcetype/>\
        <d:getetag>&quot;b134a68c554798adf769917887321c83&quot;</d:getetag>\
      </d:prop>\
      <d:status>HTTP/1.1 200 OK</d:status>\
    </d:propstat>\
    <d:propstat>\
      <d:prop>\
        <x1:share-permissions xmlns:x1="http://open-collaboration-services.org/ns"/>\
        <d:quota-available-bytes/>\
      </d:prop>\
      <d:status>HTTP/1.1 404 Not Found</d:status>\
    </d:propstat>\
  </d:response>\
</d:multistatus>\
`;

const HTTPS_OPTIONS = {
  key: fs.readFileSync(`${TLS_DIR}/${SERVER_NAME}.key`),
  cert: fs.readFileSync(`${TLS_DIR}/${SERVER_NAME}.crt`),
};

const grants = {
  localhost: {
    123456: "asdfgh",
  },
  "ocmstub1.docker": {
    123456: "asdfgh",
  },
  "ocmstub2.docker": {
    123456: "asdfgh",
  },
  "nextcloud1.docker": {
    123456: "asdfgh",
  },
  "nextcloud2.docker": {
    123456: "asdfgh",
  },
  "owncloud1.docker": {
    123456: "asdfgh",
  },
  "owncloud2.docker": {
    123456: "asdfgh",
  },
  "ocis1.docker": {
    123456: "asdfgh",
  },
  "ocis2.docker": {
    123456: "asdfgh",
  },
  "cernbox1.docker": {
    123456: "asdfgh",
  },
  "cernbox2.docker": {
    123456: "asdfgh",
  },
};

function sendHTML(res, text) {
  res.end(`<!DOCTYPE html><html><head></head><body>${text}</body></html>`);
}

function sendJSON(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

// singleton global, naively assume only one share exists at a time:
let mostRecentShareIn = {};

async function sign(message) {
  const data = Buffer.from(message);
  const signature = await crypto
    .sign("RSA-SHA256", data, privateKey)
    .toString("base64");
  console.log("signed", signature);
  return signature;
}

async function check(message, signature) {
  console.log("SENDER VERIFY", message, signature, publicKey);
  const data = Buffer.from(message);
  const verify = await crypto.verify(
    "RSA-SHA256",
    data,
    publicKey,
    Buffer.from(signature, "base64")
  );
  console.log("verify done", verify);
  return verify;
}

// Extract public key from either PEM string or {publicKeyPem: ...} object
function extractPublicKey(keyData) {
  if (typeof keyData === "string") {
    return keyData;
  }
  if (keyData && typeof keyData === "object" && keyData.publicKeyPem) {
    return keyData.publicKeyPem;
  }
  return keyData; // Return as-is and let crypto fail with a clear error
}

async function verify(message, signature, fqdn) {
  const senderConfig = await getServerConfigForServer(fqdn);
  const senderPubKey = extractPublicKey(senderConfig.config.publicKey);
  console.log("fetched sender pub key", senderConfig, senderPubKey);
  console.log("RECIPIENT VERIFY", message, signature, senderPubKey);
  const data = Buffer.from(message);
  const verify = await crypto.verify(
    "RSA-SHA256",
    data,
    senderPubKey,
    Buffer.from(signature, "base64")
  );
  console.log("verify done", verify);
  return verify;
}

async function getServerFqdnForUser(otherUser) {
  console.log("getServerFqdnForUser", otherUser);

  let otherServer = otherUser
    .split("@")
    .splice(1)
    .join("@")
    .replace("\\/", "/");
  console.log(otherServer);
  if (otherServer.startsWith("http://")) {
    otherServer = otherServer.substring("http://".length);
  } else if (otherServer.startsWith("https://")) {
    otherServer = otherServer.substring("http://".length);
  }
  if (otherServer.endsWith("/")) {
    otherServer = otherServer.substring(0, otherServer.length - 1);
  }
  return otherServer;
}

async function getServerConfigForServer(fqdn) {
  console.log("fetching", `https://${fqdn}/ocm-provider/`);
  const configResult = await fetch(`https://${fqdn}/ocm-provider/`);
  return { config: await configResult.json(), fqdn };
}

async function getServerConfigForUser(otherUser) {
  const fqdn = await getServerFqdnForUser(otherUser);
  return getServerConfigForServer(fqdn);
}

async function notifyProvider(obj, notif) {
  console.log("notifyProvider", obj, notif);
  const { config } = await getServerConfigForUser(
    obj.sender || obj.sender || `${obj.owner}@${obj.meshProvider}`
  );
  if (config.endPoint.substr(-1) == "/") {
    config.endPoint = config.endPoint.substring(0, config.endPoint.length - 1);
  }

  const postRes = await fetch(`${config.endPoint}/notifications`, {
    method: "POST",
    body: JSON.stringify(notif),
  });
  console.log("notification sent!", postRes.status, await postRes.text());
}

async function forwardInvite(invite) {
  console.log("forwardInvite", invite);
  const { config, fqdn } = await getServerConfigForUser(invite);
  console.log("discovered", config, fqdn);
  if (!config.endPoint) {
    config.endPoint = process.env.FORCE_ENDPOINT;
  }

  const inviteSpec = {
    invite: {
      token: invite.split("@")[0],
      userId: "marie",
      recipientProvider: "stub2.docker",
      name: "Marie Curie",
      email: "marie@cesnet.cz",
    },
  };
  let endPoint = config.endPoint || config.endpoint;
  if (endPoint.substr(-1) == "/") {
    endPoint = endPoint.substring(0, endPoint.length - 1);
  }
  console.log(
    "posting",
    `${endPoint}/invites/accept`,
    JSON.stringify(inviteSpec, null, 2)
  );
  const postRes = await fetch(`${endPoint}/invites/accept`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(inviteSpec, null, 2),
  });
  console.log("invite forwarded", postRes.status, await postRes.text());
}

function getDigest(body) {
  return "SHA-256=" + crypto.createHash("sha256").update(body).digest("base64");
}

async function generateSignatureHeaders(body, endPoint, method) {
  const urlObj = new URL(endPoint);
  const path = urlObj.pathname;
  const target = `${method.toLowerCase()} ${path}`;
  const digest = getDigest(body);
  const headers = {
    "request-target": target,
    "content-length": body.length.toString(),
    host: urlObj.host,
    date: new Date().toUTCString(),
    digest,
  };
  const message = Object.values(headers).join("\n");
  const signed = await sign(message);
  const checked = await check(message, signed);
  console.log({ checked });
  headers.signature = [
    `keyId="${SERVER_HOST}"`,
    `algorithm="rsa-sha256"`,
    `headers="${Object.keys(headers)}"`,
    `signature="${signed}"`,
  ].join(",");
  return headers;
}

async function createShare(consumer) {
  console.log("createShare", consumer);
  const { config, fqdn } = await getServerConfigForUser(consumer);
  if (!config.endPoint) {
    config.endPoint = process.env.FORCE_ENDPOINT;
  }

  const shareSpec = {
    shareWith: consumer,
    name: "from-stub.txt",
    providerId: PROVIDER_ID,
    meshProvider: MESH_PROVIDER,
    owner: `${USER}@${SERVER_HOST}`,
    ownerDisplayName: USER,
    sender: `${USER}@${SERVER_HOST}`,
    senderDisplayName: USER,
    shareType: "user",
    resourceType: "file",
    code: "123456",
    protocol: {
      name: "webdav",
      options: {
        sharedSecret: "shareMeNot",
      },
      webdav: {
        sharedSecret: "shareMeNot",
        URI: `https://${SERVER_HOST}/webdav-api/file.txt`,
      },
    },
  };
  console.log(shareSpec, shareSpec.protocol);
  if (config.endPoint.endsWith("/")) {
    config.endPoint = config.endPoint.substring(0, config.endPoint.length - 1);
  }

  const body = JSON.stringify(shareSpec, null, 2);
  const sharesEndpoint = `${config.endPoint}/shares`;
  const headers = await generateSignatureHeaders(body, sharesEndpoint, "POST");
  headers["content-type"] = "application/json";

  console.log("signature headers generated", headers);

  const postRes = await fetch(`${config.endPoint}/shares`, {
    method: "POST",
    headers,
    body,
  });
  console.log("outgoing share created!", postRes.status, await postRes.text());
  return fqdn;
}

function expectHeader(headers, name, expected) {
  if (headers[name] === expected) {
    console.log(`header ${name} OK`, expected);
  } else {
    console.log(
      `header ${name} missing or wrong`,
      JSON.stringify(headers),
      expected
    );
  }
}

function checkExpectedHeaders(received, expected, onesToCheck) {
  onesToCheck.forEach((name) => expectHeader(received, name, expected[name]));
}

async function fetchAccessToken(tokenEndpoint, code) {
  const body = JSON.stringify(
    {
      grant_type: `ocm_authorization_code`,
      code,
      client_id: SERVER_HOST,
    },
    null,
    2
  );
  const headers = await generateSignatureHeaders(body, tokenEndpoint, "POST");
  headers["content-type"] = "application/json";
  const tokenResult = await fetch(tokenEndpoint, {
    method: "POST",
    body,
    headers,
  });
  const response = await tokenResult.json();
  console.log("got token response", response);
  return response;
}

async function checkSignature(bodyIn, headersIn, url, method) {
  const urlObj = new URL(url);
  const target = `${method.toLowerCase()} ${urlObj.pathname}`;
  console.log("checking signature");
  const digest = getDigest(bodyIn);
  const headers = {
    "request-target": target,
    "content-length": bodyIn.length.toString(),
    host: SERVER_HOST,
    date: headersIn.date,
    digest,
  };
  const message = Object.values(headers).join("\n");
  console.log(message);
  checkExpectedHeaders(headersIn, headers, [
    "request-target",
    "content-length",
    "host",
    "digest",
  ]);
  const rx =
    /^keyId=\"(.*)\"\,algorithm=\"(.*)\"\,headers\=\"(.*)\",signature\=\"(.*)\"$/g;
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

// Parse request body based on content-type
function parseRequestBody(bodyIn, contentType) {
  if (!bodyIn) return null;

  // JSON body
  if (contentType && contentType.includes("application/json")) {
    return JSON.parse(bodyIn);
  }

  // Form-urlencoded body (for token endpoint per RFC)
  if (
    contentType &&
    contentType.includes("application/x-www-form-urlencoded")
  ) {
    const params = new URLSearchParams(bodyIn);
    const result = {};
    for (const [key, value] of params) {
      result[key] = value;
    }
    return result;
  }

  // Try JSON as default
  try {
    return JSON.parse(bodyIn);
  } catch (e) {
    return null;
  }
}

// Get path without query string
function getPath(reqUrl) {
  const idx = reqUrl.indexOf("?");
  return idx >= 0 ? reqUrl.substring(0, idx) : reqUrl;
}

const server = https.createServer(HTTPS_OPTIONS, async (req, res) => {
  console.log(req.method, req.url, req.headers);
  let bodyIn = "";

  req.on("data", (chunk) => {
    console.log("CHUNK", chunk.toString());
    bodyIn += chunk.toString();
  });

  req.on("end", async () => {
    try {
      const path = getPath(req.url);
      const route = core.resolveProtocolRoute(path);

      // Token endpoint - uses core handler
      if (route && route.id === "ocm.token" && req.method === "POST") {
        const signingServer = await checkSignature(
          bodyIn,
          req.headers,
          `https://${SERVER_HOST}${req.url}`,
          "POST"
        );
        console.log("token request", bodyIn, signingServer);

        const contentType = req.headers["content-type"] || "";
        let params;
        try {
          params = parseRequestBody(bodyIn, contentType);
        } catch (e) {
          sendJSON(res, 400, { message: "Cannot parse request body" });
          return;
        }

        if (!params) {
          sendJSON(res, 400, { message: "Cannot parse request body" });
          return;
        }

        // Normalize to core handler format
        const request = {
          grantType: params.grant_type,
          clientId: params.client_id,
          code: params.code,
        };

        const result = core.handleTokenRequest(request, { grants });
        sendJSON(res, result.status, result.body);
      }
      // Generate invite token (helper, stays in stub)
      else if (
        req.url === "/ocm/generate-invite-token" &&
        req.method === "GET"
      ) {
        console.log("generate-invite-token request");
        sendJSON(res, 200, {
          token: STUB_INVITE_TOKEN,
          inviteLink: `${SERVER_ROOT}/accept-invite?token=${STUB_INVITE_TOKEN}&providerDomain=${SERVER_HOST}`,
          user: USER,
          providerDomain: SERVER_HOST,
        });
      }
      // Invite-accepted endpoint (spec-shaped) - uses core handler
      else if (
        route &&
        route.id === "ocm.inviteAccepted" &&
        req.method === "POST"
      ) {
        console.log("invite-accepted request", bodyIn);
        let payload;
        try {
          payload = JSON.parse(bodyIn);
        } catch (e) {
          sendJSON(res, 400, { message: "Cannot parse JSON body" });
          return;
        }

        const ctx = {
          validToken: STUB_INVITE_TOKEN,
          acceptedInvites,
          localUser: LOCAL_USER,
        };

        const result = core.handleInviteAcceptedInbound(payload, ctx);
        if (result.status === 200) {
          console.log(
            "Invite accepted, contact established:",
            payload.recipientProvider,
            acceptedInvites[payload.recipientProvider]
          );
        }
        sendJSON(res, result.status, result.body);
      }
      // Invites/accept endpoint (Reva-style) - uses core handler
      else if (
        route &&
        route.id === "ocm.invitesAccept" &&
        req.method === "POST"
      ) {
        console.log("invites/accept request (Reva-style)", bodyIn);
        let payload;
        try {
          payload = JSON.parse(bodyIn);
        } catch (e) {
          sendJSON(res, 400, { message: "Cannot parse JSON body" });
          return;
        }

        const ctx = {
          validToken: STUB_INVITE_TOKEN,
          acceptedInvites,
          localUser: LOCAL_USER,
        };

        const result = core.handleInvitesAcceptInbound(payload, ctx);
        if (result.status === 200) {
          const invite = payload.invite || payload;
          console.log(
            "Reva-style invite accepted:",
            invite.recipientProvider,
            acceptedInvites[invite.recipientProvider]
          );
        }
        sendJSON(res, result.status, result.body);
      }
      // Accept-invite UI page (Stub as receiver, forwarding to remote inviter)
      else if (
        (req.url.startsWith("/accept-invite") ||
          req.url.startsWith("/ocm/accept-invite")) &&
        req.method === "GET"
      ) {
        const urlObj = new URL(req.url, SERVER_ROOT);
        const token = urlObj.searchParams.get("token");
        const providerDomain = urlObj.searchParams.get("providerDomain");
        console.log("accept-invite request", { token, providerDomain });
        if (!token || !providerDomain) {
          res.writeHead(400);
          sendHTML(
            res,
            "Missing required query parameters: token, providerDomain"
          );
          return;
        }
        try {
          // Use ocm-core for discovery
          let discovery;
          try {
            discovery = await core.discoverPeer(providerDomain, { fetch });
          } catch (e) {
            // Fallback to legacy discovery
            const { config } = await getServerConfigForServer(providerDomain);
            discovery = {
              endPoint: core.trimTrailingSlash(
                config.endPoint || config.endpoint
              ),
              _raw: config,
            };
          }

          let endPoint = discovery.endPoint;
          if (!endPoint) {
            res.writeHead(500);
            sendHTML(res, `Could not discover endpoint for ${providerDomain}`);
            return;
          }

          // Build AcceptedInvite payload per OCM spec
          const acceptPayload = {
            recipientProvider: SERVER_HOST,
            token: token,
            userID: USER,
            email: `${USER}@${SERVER_HOST}`,
            name: "Albert Einstein",
          };

          // Try spec endpoint first, then fall back to Reva-style
          let inviteAcceptUrl = `${endPoint}/invite-accepted`;
          console.log(
            "Forwarding invite to OCM provider:",
            inviteAcceptUrl,
            JSON.stringify(acceptPayload, null, 2)
          );

          let postRes = await fetch(inviteAcceptUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(acceptPayload),
          });

          // If spec endpoint fails with 404/501, try Reva-style
          if (postRes.status === 404 || postRes.status === 501) {
            console.log(
              "Spec endpoint not supported, trying Reva-style /invites/accept"
            );
            inviteAcceptUrl = `${endPoint}/invites/accept`;
            const revaPayload = {
              invite: {
                token: token,
                userId: USER,
                recipientProvider: SERVER_HOST,
                name: "Albert Einstein",
                email: `${USER}@${SERVER_HOST}`,
              },
            };
            postRes = await fetch(inviteAcceptUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(revaPayload),
            });
          }

          const responseText = await postRes.text();
          console.log("Invite response:", postRes.status, responseText);

          // Treat 200 OK as success, and 409 "already accepted" as a
          // user-visible success as well. From the user's perspective,
          // an already-accepted invite means the contact is established.
          if (postRes.ok || postRes.status === 409) {
            // Store or confirm the contact on our side for 2xx responses.
            // For 409 we rely on previously stored state.
            if (postRes.ok) {
              try {
                const remoteUser = JSON.parse(responseText);
                acceptedInvites[providerDomain] = {
                  userID: remoteUser.userID,
                  email: remoteUser.email,
                  name: remoteUser.name,
                };
              } catch (e) {
                acceptedInvites[providerDomain] = {
                  userID: "remote-user",
                  email: "",
                  name: "",
                };
              }
            }

            const already =
              postRes.status === 409
                ? " (already accepted earlier)"
                : "";
            sendHTML(
              res,
              `<h1>Invite Accepted</h1><p>You are now connected to ${providerDomain}${already}</p><p>Response: ${responseText}</p>`
            );
          } else {
            sendHTML(
              res,
              `<h1>Invite Failed</h1><p>Could not accept invite from ${providerDomain}</p><p>Status: ${postRes.status}</p><p>Response: ${responseText}</p>`
            );
          }
        } catch (e) {
          console.error("Error forwarding invite:", e);
          res.writeHead(500);
          sendHTML(
            res,
            `<h1>Error</h1><p>Failed to forward invite: ${e.message}</p>`
          );
        }
      }
      // Legacy redirect to accept-invite
      else if (
        req.url.startsWith("/ocm/invites/forward") ||
        req.url.startsWith("/invites/forward")
      ) {
        const urlObj = new URL(req.url, SERVER_ROOT);
        const token = urlObj.searchParams.get("token");
        const providerDomain = urlObj.searchParams.get("providerDomain");
        res.writeHead(302, {
          Location: `/accept-invite?token=${token}&providerDomain=${providerDomain}`,
        });
        res.end();
      }
      // WebDAV endpoints
      else if (
        (req.url === "/webdav-api/" || req.url === "/public.php/webdav/") &&
        req.method === "PROPFIND"
      ) {
        console.log("PROPFIND", req.headers["authorization"]);
        res.setHeader("Content-Type", "application/xml; charset=utf-8");
        res.writeHead(207);
        res.end(PROPFIND_RESPONSE);
      } else if (req.url === "/webdav-api/file.txt") {
        console.log("API access", req.headers["authorization"]);
        if (req.headers["authorization"] === `Bearer asdfgh`) {
          res.end("The content of the file, well done!");
        } else if (typeof req.headers["authorization"] === "string") {
          res.writeHead(403);
          res.end("No access, sorry\n");
        } else {
          res.writeHead(req.headers["authorization"] ? 403 : 401);
          res.end(
            "Unauthorized: Please use a short-lived bearer for this API. You can exchange the code from the share at the token endpoint using httpsig\n"
          );
        }
      }
      // Discovery endpoints - use ocm-core
      else if (
        req.url === "/ocm-provider" ||
        req.url === "/ocm-provider/" ||
        req.url === "/.well-known/ocm" ||
        req.url === "/.well-known/ocm/"
      ) {
        sendJSON(res, 200, getProviderDescriptor());
      }
      // Shares endpoint (stays in stub for now)
      else if (req.url === "/ocm/shares") {
        console.log("yes /ocm/shares");
        try {
          mostRecentShareIn = JSON.parse(bodyIn);
        } catch (e) {
          sendJSON(res, 400, { message: "Cannot parse JSON" });
          return;
        }
        if (typeof req.headers["signature"] === "string") {
          const signingServer = await checkSignature(
            bodyIn,
            req.headers,
            `https://${SERVER_HOST}${req.url}`,
            "POST"
          );
          const claimedServer = await getServerFqdnForUser(
            mostRecentShareIn.sender
          );
          if (signingServer !== claimedServer) {
            console.log(
              "ALARM! Claimed server does not match signing server",
              claimedServer,
              signingServer
            );
          }
          if (mostRecentShareIn?.code) {
            console.log(
              "code received! exchanging it for token...",
              mostRecentShareIn?.code
            );
            const { config, fqdn } = await getServerConfigForServer(
              claimedServer
            );
            const urlObj = new URL(config.endPoint, `https://${fqdn}`);
            const tokenEndpoint = `${urlObj.href}/token`;
            console.log("token endpoint discovered", tokenEndpoint);
            const token = await fetchAccessToken(
              tokenEndpoint,
              mostRecentShareIn?.code
            );
            console.log("will now use token to access webdav", token);
            const result = await fetch(
              mostRecentShareIn?.protocol?.webdav?.URI,
              {
                headers: {
                  authorization: `Bearer ${token.access_token}`,
                },
              }
            );
            console.log("API accessed", result.status, await result.text());
          }
        } else {
          console.log("unsigned request to create share");
        }

        res.writeHead(201, {
          "Content-Type": "application/json",
        });
        res.end(
          JSON.stringify(
            {
              recipientDisplayName: "Marie Curie",
            },
            null,
            2
          )
        );
      }
      // UI/Helper endpoints (stay in stub)
      else if (req.url.startsWith("/publicLink")) {
        console.log("yes publicLink");
        const urlObj = new URL(req.url, SERVER_ROOT);
        if (urlObj.search.startsWith("?saveTo=")) {
          console.log("creating share", urlObj.search);
          const otherServerRoot = await createShare(
            decodeURIComponent(urlObj.search).substring("?saveTo=".length)
          );
          res.writeHead(301, {
            location: otherServerRoot,
          });
          sendHTML(res, `Redirecting you to ${otherServerRoot}`);
        } else {
          sendHTML(res, "yes publicLink, saveTo?");
        }
      } else if (req.url.startsWith("/forwardInvite")) {
        console.log("yes forwardInvite");
        const urlObj = new URL(req.url, SERVER_ROOT);
        await forwardInvite(
          decodeURIComponent(urlObj.search).substring("?".length)
        );
        sendHTML(res, "yes forwardInvite");
      } else if (req.url.startsWith("/shareWith")) {
        const urlObj = new URL(req.url, SERVER_ROOT);
        const recipient = decodeURIComponent(urlObj.search).substring(
          "?".length
        );
        if (typeof sharesSent[recipient] === "undefined") {
          console.log("yes shareWith");
          sharesSent[recipient] = true;
          try {
            await createShare(recipient);
            sendHTML(res, "yes shareWith (success)");
          } catch (e) {
            sendHTML(res, "yes shareWith (fail)");
          }
        } else {
          console.log("yes shareWith (ignoring)");
          sendHTML(res, "yes shareWith (ignoring)");
        }
      } else if (req.url.startsWith("/acceptShare")) {
        console.log("yes acceptShare");
        try {
          console.log(
            "Creating notif to accept share, obj =",
            mostRecentShareIn
          );
          const notif = {
            type: "SHARE_ACCEPTED",
            resourceType: mostRecentShareIn.resourceType,
            providerId: mostRecentShareIn.providerId,
            notification: {
              sharedSecret: mostRecentShareIn.protocol
                ? mostRecentShareIn.protocol.options
                  ? mostRecentShareIn.protocol.options.sharedSecret
                  : undefined
                : undefined,
              message: "Recipient accepted the share",
            },
          };
          notifyProvider(mostRecentShareIn, notif);
        } catch (e) {
          console.error(e);
          sendHTML(res, `no acceptShare - fail`);
        }
        sendHTML(res, "yes acceptShare");
      } else if (req.url.startsWith("/deleteAcceptedShare")) {
        console.log("yes deleteAcceptedShare");
        const notif = {
          type: "SHARE_DECLINED",
          message: "I don't want to use this share anymore.",
          id: mostRecentShareIn.id,
          createdAt: new Date(),
        };
        console.log("deleting share", mostRecentShareIn);
        try {
          notifyProvider(mostRecentShareIn, notif);
        } catch (e) {
          sendHTML(res, `no deleteAcceptedShare - fail`);
        }
        sendHTML(res, "yes deleteAcceptedShare");
      } else if (req.url.startsWith("/?")) {
        console.log("yes /", mostRecentShareIn);
        if (req.url.indexOf("session=active") != -1) {
          sendHTML(
            res,
            `<form method="get">
            <input type="submit" value="Log out">
          </form> /` + JSON.stringify(mostRecentShareIn, null, 2)
          );
        } else {
          sendHTML(
            res,
            `<form method="get">
            <input type="hidden" name="session" value="active">
            <input type="submit" value="Log in">
          </form> /` + JSON.stringify(mostRecentShareIn, null, 2)
          );
        }
      } else if (req.url.startsWith("/meshdir?")) {
        const queryObject = url.parse(req.url, true).query;
        console.log(queryObject);
        const config = {
          nextcloud1:
            "https://nextcloud1.docker/index.php/apps/sciencemesh/accept",
          owncloud1:
            "https://owncloud1.docker/index.php/apps/sciencemesh/accept",
          nextcloud2:
            "https://nextcloud2.docker/index.php/apps/sciencemesh/accept",
          owncloud2:
            "https://owncloud2.docker/index.php/apps/sciencemesh/accept",
          ocmstub1: "https://ocmstub1.docker/accept-invite",
          ocmstub2: "https://ocmstub2.docker/accept-invite",
          stub2: "https://ocmstub2.docker/accept-invite",
          cernbox1: "https://cernbox1.docker/accept-invite",
          cernbox2: "https://cernbox2.docker/accept-invite",
          revad2: undefined,
        };
        const items = [];
        const scriptLines = [];
        Object.keys(config).forEach((key) => {
          if (typeof config[key] === "string") {
            items.push(`  <li><a id="${key}">${key}</a></li>`);
            scriptLines.push(
              `  document.getElementById("${key}").setAttribute("href", "${config[key]}"+window.location.search);`
            );
          } else {
            const params = new URLSearchParams(req.url.split("?")[1]);
            console.log(params);
            const token = params.get("token");
            const providerDomain = params.get("providerDomain");
            items.push(
              `  <li>${key}: Please run <tt>ocm-invite-forward -idp ${providerDomain} -token ${token}</tt> in Reva's CLI tool.</li>`
            );
          }
        });

        console.log("meshdir", mostRecentShareIn);
        sendHTML(
          res,
          `Welcome to the meshdir stub. Please click a server to continue to:\n<ul>${items.join(
            "\n"
          )}</ul>\n<script>\n${scriptLines.join("\n")}\n</script>\n`
        );
      } else {
        console.log("not recognized");
        sendHTML(res, `OK ${req.url}`);
      }
    } catch (e) {
      console.error(e);
      res.writeHead(500);
      sendJSON(res, 500, { message: "Internal Server Error" });
    }
  });
});

server.listen(443);
console.log(`OCM-stub listening on https://${SERVER_HOST}`);
console.log(
  `Browse to https://${SERVER_HOST}/ocm-provider or https://${SERVER_HOST}/shareWith?bob@${SERVER_HOST}`
);
