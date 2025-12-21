/**
 * ocm-core.js - OCM protocol logic (pure, no HTTP/TLS handling)
 *
 * This module contains spec-aligned OCM protocol logic that can be tested
 * independently of the HTTP transport layer.
 */

const OCM_BASE = "/ocm";

// URL/Path Helpers

function trimTrailingSlash(str) {
  if (typeof str !== "string") return str;
  return str.endsWith("/") ? str.slice(0, -1) : str;
}

function joinUrlPath(base, path) {
  if (!base || !path) return base || path || "";
  const cleanBase = trimTrailingSlash(base);
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  return `${cleanBase}${cleanPath}`;
}

/**
 * Normalize a URL or path field to an absolute URL.
 * Accepts: absolute URL, absolute path, or relative path.
 * @param {string} baseUrl - The base URL (e.g., https://example.org)
 * @param {string} field - The field value to normalize
 * @returns {string|null} Absolute URL or null if invalid
 */
function normalizeUrlOrPath(baseUrl, field) {
  if (!field) return null;

  // Already an absolute URL
  if (field.startsWith("https://") || field.startsWith("http://")) {
    return trimTrailingSlash(field);
  }

  // Absolute path
  if (field.startsWith("/")) {
    const base = trimTrailingSlash(baseUrl);
    return `${base}${field}`;
  }

  // Relative path (no leading slash)
  const base = trimTrailingSlash(baseUrl);
  return `${base}/${field}`;
}

// Local Discovery

/**
 * Build the local discovery response for this server.
 * @param {string} serverHost - The server's FQDN (e.g., ocmstub1.docker)
 * @param {object} opts - Options including publicKey
 * @returns {object} Discovery response per OCM spec
 */
function getLocalDiscovery(serverHost, opts = {}) {
  return {
    enabled: true,
    apiVersion: "1.2.0",
    endPoint: `https://${serverHost}${OCM_BASE}`,
    resourceTypes: [
      {
        name: "file",
        shareTypes: ["user", "group"],
        protocols: {
          webdav: "/webdav-api/",
        },
      },
    ],
    capabilities: ["invites", "exchange-token"],
    tokenEndPoint: `${OCM_BASE}/token`,
    inviteAcceptDialog: "/accept-invite",
    publicKey: opts.publicKey || null,
  };
}

// Peer Discovery

/**
 * Discover a remote OCM peer's configuration.
 * @param {string} fqdn - The peer's FQDN
 * @param {object} deps - Dependencies (fetch function)
 * @returns {Promise<object>} Normalized discovery info
 */
async function discoverPeer(fqdn, deps = {}) {
  const fetchFn = deps.fetch || globalThis.fetch;
  const baseUrl = `https://${fqdn}`;

  let discoveryData = null;
  let lastError = null;

  // Try /.well-known/ocm first, then /ocm-provider
  for (const path of ["/.well-known/ocm", "/ocm-provider"]) {
    try {
      const url = `${baseUrl}${path}`;
      const response = await fetchFn(url);
      if (response.ok) {
        discoveryData = await response.json();
        break;
      }
    } catch (e) {
      lastError = e;
    }
  }

  if (!discoveryData) {
    throw {
      status: 502,
      code: "DISCOVERY_FAILED",
      message: `Could not discover OCM endpoint for ${fqdn}`,
      details: lastError?.message,
    };
  }

  // Validate required fields
  const required = ["enabled", "apiVersion", "endPoint", "resourceTypes"];
  for (const field of required) {
    if (discoveryData[field] === undefined) {
      throw {
        status: 502,
        code: "DISCOVERY_INVALID",
        message: `Discovery response missing required field: ${field}`,
      };
    }
  }

  // Normalize endPoint (must be absolute https:// URL)
  let endPoint = trimTrailingSlash(discoveryData.endPoint);
  if (!endPoint.startsWith("https://")) {
    throw {
      status: 502,
      code: "DISCOVERY_INVALID",
      message: "Discovery endPoint must be an absolute https:// URL",
    };
  }

  // Normalize optional URL/path fields
  const tokenEndPoint = discoveryData.tokenEndPoint
    ? normalizeUrlOrPath(baseUrl, discoveryData.tokenEndPoint)
    : null;

  let inviteAcceptDialog = null;
  if (discoveryData.inviteAcceptDialog) {
    try {
      inviteAcceptDialog = normalizeUrlOrPath(
        baseUrl,
        discoveryData.inviteAcceptDialog
      );
    } catch (e) {
      console.warn(
        `Could not normalize inviteAcceptDialog for ${fqdn}:`,
        e.message
      );
    }
  }

  return {
    enabled: discoveryData.enabled,
    apiVersion: discoveryData.apiVersion,
    endPoint,
    resourceTypes: discoveryData.resourceTypes,
    capabilities: discoveryData.capabilities || [],
    publicKey: discoveryData.publicKey || null,
    tokenEndPoint,
    inviteAcceptDialog,
    provider: discoveryData.provider || null,
    _raw: discoveryData,
  };
}

// Route Registry

const PROTOCOL_ROUTES = [
  {
    id: "ocm.inviteAccepted",
    path: `${OCM_BASE}/invite-accepted`,
    aliases: ["/invite-accepted"],
    method: "POST",
  },
  {
    id: "ocm.invitesAccept",
    path: `${OCM_BASE}/invites/accept`,
    aliases: ["/invites/accept"],
    method: "POST",
  },
  {
    id: "ocm.token",
    path: `${OCM_BASE}/token`,
    aliases: [],
    method: "POST",
  },
];

function getProtocolRoutes() {
  return PROTOCOL_ROUTES;
}

/**
 * Resolve a request path to a protocol route.
 * @param {string} path - The request path (without query string)
 * @returns {object|null} The matching route or null
 */
function resolveProtocolRoute(path) {
  const normalizedPath = trimTrailingSlash(path);
  for (const route of PROTOCOL_ROUTES) {
    if (route.path === normalizedPath) {
      return route;
    }
    for (const alias of route.aliases) {
      if (alias === normalizedPath) {
        return route;
      }
    }
  }
  return null;
}

// Core Handlers

/**
 * Handle inbound invite-accepted request (spec-shaped).
 * @param {object} payload - The AcceptedInvite payload
 * @param {object} ctx - Context with validToken, acceptedInvites, localUser
 * @returns {object} Response with status and body
 */
function handleInviteAcceptedInbound(payload, ctx) {
  const { recipientProvider, token, userID, email, name } = payload || {};

  // Validate required fields
  if (!recipientProvider || !token || !userID) {
    return {
      status: 400,
      body: {
        message: "Missing required fields: recipientProvider, token, userID",
      },
    };
  }

  // Validate token
  if (token !== ctx.validToken) {
    return {
      status: 400,
      body: { message: "Invalid or expired invite token" },
    };
  }

  // Check for duplicate acceptance
  if (ctx.acceptedInvites[recipientProvider]) {
    return {
      status: 409,
      body: { message: "Invite already accepted from this provider" },
    };
  }

  // Store the accepted invite
  ctx.acceptedInvites[recipientProvider] = { userID, email, name };

  // Return local user info
  return {
    status: 200,
    body: {
      userID: ctx.localUser.userID,
      email: ctx.localUser.email,
      name: ctx.localUser.name,
    },
  };
}

/**
 * Handle inbound invites/accept request (Reva-style).
 * Unwraps the nested invite object if present.
 * @param {object} payload - The request payload (may have nested invite)
 * @param {object} ctx - Context with validToken, acceptedInvites, localUser
 * @returns {object} Response with status and body
 */
function handleInvitesAcceptInbound(payload, ctx) {
  // Reva sends: { invite: { token, userId, recipientProvider, name, email } }
  const invite = payload?.invite || payload || {};

  // Map Reva field names to spec field names
  const normalized = {
    recipientProvider: invite.recipientProvider,
    token: invite.token,
    userID: invite.userId || invite.userID,
    email: invite.email,
    name: invite.name,
  };

  return handleInviteAcceptedInbound(normalized, ctx);
}

/**
 * Handle token exchange request.
 * @param {object} request - Normalized request { grantType, clientId, code }
 * @param {object} ctx - Context with grants table
 * @returns {object} Response with status and body
 */
function handleTokenRequest(request, ctx) {
  const { grantType, clientId, code } = request || {};

  // Validate grant_type (accept both RFC and legacy)
  if (
    grantType !== "authorization_code" &&
    grantType !== "ocm_authorization_code"
  ) {
    return {
      status: 400,
      body: { message: "Invalid grant_type" },
    };
  }

  // Validate client
  if (!clientId || typeof ctx.grants[clientId] !== "object") {
    return {
      status: 403,
      body: { message: `No grants found for client ${clientId}` },
    };
  }

  // Validate code
  if (!code || typeof ctx.grants[clientId][code] !== "string") {
    return {
      status: 403,
      body: { message: `Grant ${code} not found for client ${clientId}` },
    };
  }

  // Return token response
  return {
    status: 200,
    body: {
      access_token: ctx.grants[clientId][code],
      token_type: "bearer",
      expires_in: 3600,
      refresh_token: "qwertyuiop",
    },
  };
}

// State Factory

/**
 * Create invite state for a stub instance.
 * @param {string} validToken - The valid invite token
 * @returns {object} State object with acceptedInvites map
 */
function createInviteState(validToken) {
  return {
    acceptedInvites: {},
    validToken,
  };
}

// Exports

module.exports = {
  // Constants
  OCM_BASE,

  // URL helpers
  trimTrailingSlash,
  joinUrlPath,
  normalizeUrlOrPath,

  // Discovery
  getLocalDiscovery,
  discoverPeer,

  // Route registry
  getProtocolRoutes,
  resolveProtocolRoute,

  // Handlers
  handleInviteAcceptedInbound,
  handleInvitesAcceptInbound,
  handleTokenRequest,

  // State
  createInviteState,
};
