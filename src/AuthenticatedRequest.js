/**
 * Dependencies
 */
const {JWT} = require('@solid/jose')
const Credential = require('./Credential')

/**
 * Errors
 */
const {
  BadRequestError,
  ForbiddenError,
  // InternalServerError,
  UnauthorizedError
} = require('./errors')

const LEGACY_POP = 'legacyPop'
const DPOP = 'dpop'

/**
 * AuthenticatedRequest
 */
class AuthenticatedRequest {

  /**
   * constructor
   *
   * @param {ResourceServer} rs
   * @param {IncomingRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   *
   * @param {Object}   options
   * @param {boolean} [options.query]
   * @param {boolean} [options.optional]
   * @param {string}  [options.realm]
   * @param {Object}  [options.allow]
   * @param {Object}  [options.deny]
   * @param {Array}   [options.scopes]
   * @param {string}  [options.tokenProperty]
   * @param {string}  [options.claimsProperty]
   * @param {boolean} [options.handleErrors]
   */
  constructor (rs, req, res, next, options) {
    this.rs = rs
    this.req = req
    this.res = res
    this.next = next
    this.options = {
      ...options,
      tokenTypesSupported: [DPOP, LEGACY_POP]
    }
  }

  /**
   * authenticate
   *
   * @description
   * Authenticate an HTTP request by validating a signed JWT bearer
   * token. Handles error responses and, when authentication succeeds,
   * passes control to the middleware stack.
   *
   * @param {ResourceServer} rs
   * @param {IncomingMessage} req
   * @param {ServerResponse} res
   * @param {Function} next
   * @param {Object} options
   */
  static authenticate (rs, req, res, next, options) {
    let request = new AuthenticatedRequest(rs, req, res, next, options)

    // These methods on the request object are invoked in the promise chain
    // as callbacks. Each method in the chain takes a request instance and
    // assuming no error conditions are encountered, returns it, or returns
    // a promise that resolves it.
    Promise.resolve(request)
      .then(request.validateAuthorizationHeader)
      .then(request.validateQueryParameter)
      .then(request.validateBodyParameter)
      .then(request.requireAccessToken)
      .then(request.validateAccessToken)
      .then(request.success)
      .catch(error => request.error(error))
  }

  /**
   * validateAuthorizationHeader
   *
   * @description
   * Validate HTTP Authorization Header and extract bearer token credentials.
   * Trigger an error response in the event the header is misused.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  validateAuthorizationHeader (request) {
    let {token, req} = request
    let authorization = req.headers && req.headers.authorization

    if (authorization && token) {
      return request.badRequest('Multiple authentication methods')
    }

    if (authorization) {
      let components = authorization.split(' ')
      let [scheme, credentials] = components

      if (components.length !== 2) {
        return request.badRequest('Invalid authorization header')
      }

      if (
        scheme.toLowerCase() === 'bearer' &&
        request.options.tokenTypesSupported.includes(LEGACY_POP)
      ) {
        request.tokenType = 'bearer'
      } else if (
        scheme.toLowerCase() === 'dpop' &&
        request.options.tokenTypesSupported.includes(DPOP)
      ) {
        request.tokenType = 'dpop'
      } else {
        return request.badRequest('Invalid authorization scheme')
      }
      request.token = credentials
    }

    return request
  }

  /**
   * validateQueryParameter
   *
   * @description
   * Validate HTTP Query Parameter and extract bearer token credentials.
   * Trigger an error response in the event the parameter is misused. This
   * authentication is disallowed by default and must be explicitly enabled
   * by setting the `query` option to `true`.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  validateQueryParameter (request) {
    let {token, req, options} = request
    let param = req.query && req.query['access_token']

    // 💀 💀 💀 💀 💀 💀 💀         WARNING          💀 💀 💀 💀 💀 💀 💀 💀
    //
    // DO NOT ALLOW THIS AUTHENTICATION METHOD UNLESS THE USER
    // EXPLICITLY ENABLES IT. CHANCES ARE ITS USE IS NOT SECURE.
    //
    // SEE RFC 6750 SECTIONS 2.3 AND 5.3 FOR DETAILS.
    //
    //    https://tools.ietf.org/html/rfc6750#section-2.3
    //    https://tools.ietf.org/html/rfc6750#section-5.3
    //
    // 💀 💀 💀 💀 💀 💀 💀    YOU HAVE BEEN WARNED  💀 💀 💀 💀 💀 💀 💀 💀

    if (param && options.query !== true) {
      return request.badRequest('Invalid authentication method')
    }

    if (param && token) {
      return request.badRequest('Multiple authentication methods')
    }

    if (param) {
      request.token = param
    }

    return request
  }

  /**
   * validateBodyParameter
   *
   * @description
   * Validate HTTP Form Post Parameter and extract bearer token credentials.
   * Trigger an error response in the event the form parameter is misused.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  validateBodyParameter (request) {
    let {token, req} = request
    let param = req.body && req.body['access_token']
    let contentType = req.headers && req.headers['content-type']

    if (param && token) {
      return request.badRequest('Multiple authentication methods')
    }

    if (param && !contentType.includes('application/x-www-form-urlencoded')) {
      return request.badRequest('Invalid Content-Type')
    }

    if (param) {
      request.token = param
    }

    return request
  }

  /**
   * requireAccessToken
   *
   * @description
   * Ensure a bearer token is included in the request unless authentication
   * is optional.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  requireAccessToken (request) {
    let {token, options} = request
    let {realm, optional} = options

    if (!token && optional !== true) {
      return request.unauthorized({realm})
    }

    return request
  }

  /**
   * validateAccessToken
   *
   * @description
   * Validate all aspects of an access token.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  validateAccessToken (request) {
    let {token, options} = request

    if (options.optional && !token) {
      // Token not required and none present -- pass through
      return Promise.resolve(request)
    }

    return Promise.resolve(request)
      .then(request.decode)
      .then(request.validatePoPToken)
      .then(request.allow)
      .then(request.deny)
      .then(request.resolveKeys)
      .then(request.verifySignature)
      .then(request.validateExpiry)
      .then(request.validateNotBefore)
      .then(request.validateScope)
  }

  /**
   * decode
   *
   * @description
   * Decode a JWT Bearer Token and set the decoded object on the
   * AuthenticatedRequest instance.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  decode (request) {
    let jwt
    let {token, options: {realm}} = request

    // decode and validate the token
    try {
      jwt = JWT.decode(token)
    } catch (error) {
      return request.unauthorized({
        realm,
        error: 'invalid_token',
        error_description: 'Access token is not a JWT'
      })
    }

    try {
      request.credential = Credential.from(jwt, request)
    } catch (err) {
      return request.badRequest(err.error_description)
    }

    return request
  }

  /**
   * validatePoPToken
   *
   * @description
   * Validate the outer Proof of Possession token, if applicable.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {Promise<AuthenticatedRequest>}
   */
  validatePoPToken (request) {
    let {credential, options: {realm}} = request

    if (!credential.isPoPToken) {
      return Promise.resolve(request)  // only applies to PoP tokens
    }

    return credential.validatePoPToken()

      .then(() => request)

      .catch(err => {
        return request.unauthorized({
          realm,
          error: err.error || 'invalid_token',
          error_description: err.error_description || 'Invalid PoP token'
        })
      })
  }

  /**
   * allow
   *
   * @description
   * Enforce access restrictions for issuers, audience, and subjects
   * configured using the "allow" option.
   *
   * @param {AuthenticatedRequest} request
   *
   * @throws {ForbiddenError}
   *
   * @returns {AuthenticatedRequest}
   */
  allow (request) {
    let { options: { allow } } = request

    if (!allow) {
      return request
    }

    if (request.tokenType === 'bearer') {
      request.allowAudience(request)
    }

    request.allowIssuer(request)

    request.allowSubject(request)

    return request
  }

  /**
   * allowAudience
   *
   * @description
   * Filters the credential's audience claim using the "allow" option.
   *
   * @param {AuthenticatedRequest} request
   *
   * @throws {ForbiddenError}
   */
  allowAudience (request) {
    let { options, credential: { aud } } = request
    let { realm, allow: { audience } } = options

    if (!audience) {
      return
    }

    if (typeof audience === 'function') {
      if (audience(aud)) {
        return  // token passes the audience filter test
      } else {
        return request.forbidden({
          realm,
          error: 'access_denied',
          error_description: 'Token does not pass the audience allow filter'
        })
      }
    }

    if (Array.isArray(aud) && !audience.some(id => aud.includes(id))) {
      return request.forbidden({
        realm,
        error: 'access_denied',
        error_description: 'Audience is not on the allowed list'
      })
    }

    if (typeof aud === 'string' && !audience.includes(aud)) {
      return request.forbidden({
        realm,
        error: 'access_denied',
        error_description: 'Audience is not on the allowed list'
      })
    }
  }

  /**
   * allowIssuer
   *
   * @description
   * Filters the credential's issuer claim using the "allow" option.
   *
   * @param {AuthenticatedRequest} request
   *
   * @throws {ForbiddenError}
   */
  allowIssuer (request) {
    let { options, credential: { iss } } = request
    let { realm, allow: { issuers } } = options

    if (!issuers) {
      return
    }

    if (typeof issuers === 'function') {
      if (issuers(iss)) {
        return  // token passes the issuer filter test
      } else {
        return request.forbidden({
          realm,
          error: 'access_denied',
          error_description: 'Token does not pass the issuer allow filter'
        })
      }
    }

    if (!issuers.includes(iss)) {
      return request.forbidden({
        realm,
        error: 'access_denied',
        error_description: 'Issuer is not on the allowed list'
      })
    }
  }

  /**
   * allowSubject
   *
   * @description
   * Filters the credential's subject claim using the "allow" option.
   *
   * @param {AuthenticatedRequest} request
   *
   * @throws {ForbiddenError}
   */
  allowSubject (request) {
    let { options, credential: { sub } } = request
    let { realm, allow: { subjects } } = options

    if (!subjects) {
      return
    }

    if (typeof subjects === 'function') {
      if (subjects(sub)) {
        return  // token passes the subjects filter test
      } else {
        return request.forbidden({
          realm,
          error: 'access_denied',
          error_description: 'Token does not pass the subject allow filter'
        })
      }
    }

    if (!subjects.includes(sub)) {
      return request.forbidden({
        realm,
        error: 'access_denied',
        error_description: 'Subject is not on the allowed list'
      })
    }
  }

  /**
   * deny
   *
   * @description
   * Enforce access restrictions for issuers, audience, and subjects
   * configured using the "deny" option.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  deny (request) {
    let {credential, options} = request
    let {deny, realm} = options

    if (!deny) {
      return request
    }

    let {iss, aud, sub} = credential
    let {issuers, audience, subjects} = deny

    if (issuers && issuers.includes(iss)) {
      return request.forbidden({
        realm,
        error: 'access_denied',
        error_description: 'Issuer is on the deny blacklist'
      })
    }

    if (Array.isArray(aud) && audience.some(id => aud.includes(id))) {
      return request.forbidden({
        realm,
        error: 'access_denied',
        error_description: 'Audience is on the deny blacklist'
      })
    }

    if (typeof aud === 'string' && audience.includes(aud)) {
      return request.forbidden({
        realm,
        error: 'access_denied',
        error_description: 'Audience is on the deny blacklist'
      })
    }

    if (subjects && subjects.includes(sub)) {
      return request.forbidden({
        realm,
        error: 'access_denied',
        error_description: 'Subject is on the deny blacklist'
      })
    }

    return request
  }

  /**
   * resolveKeys
   *
   * @description
   * Obtains the cryptographic key necessary to validate the JWT access token's
   * signature.
   *
   * Based on the "iss" claim in the JWT access token payload, obtain OpenID
   * Connect configuration and the JWT Set for the corresponding provider.
   * This data is cached by the ResourceServer. The cache can be persisted and
   * restored.
   *
   * In the event no suitable key can be matched based on the JWT "kid" header
   * or JWK "use" property, refresh the cached configuration and JWK Set for
   * the issuer and try again. If a key still cannot be found, authentication
   * fails.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  resolveKeys (request) {
    let providers = request.rs.providers
    let realm = request.options.realm
    let credential = request.credential
    let iss = credential.iss

    return providers.resolve(iss).then(provider => {
      // key matched
      if (credential.resolveKeys(provider.jwks)) {
        return request

      // try rotating keys
      } else {
        return providers.rotate(iss).then(provider => {
          // key matched
          if (credential.resolveKeys(provider.jwks)) {
            return request

          // failed to match signing key
          } else {
            return request.unauthorized({
              realm,
              error: 'invalid_token',
              error_description: 'Cannot find key to verify JWT signature'
            })
          }
        })
      }
    })
  }

  /**
   * verifySignature
   *
   * @description
   * Verify the access token signature.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  verifySignature (request) {
    let {credential, options: {realm}} = request

    return credential.verifySignature().then(verified => {
      if (!verified) {
        request.unauthorized({realm})
      }

      return request
    })
  }

  /**
   * validateExpiry
   *
   * @description
   * Ensures the access token has not expired.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  validateExpiry (request) {
    let {credential, options: {realm}} = request

    try {
      credential.validateExpiry()
    } catch (err) {
      return request.unauthorized({
        realm,
        error: err.error,
        error_description: err.error_description
      })
    }

    return request
  }

  /**
   * validateNotBefore
   *
   * @description
   * Ensures the access token has become active.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  validateNotBefore (request) {
    let {credential, options: {realm}} = request

    try {
      credential.validateNotBefore()
    } catch (err) {
      return request.unauthorized({
        realm,
        error: err.error,
        error_description: err.error_description
      })
    }

    return request
  }


  /**
   * validateScope
   *
   * @description
   * Ensures the access token has sufficient scope.
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  validateScope (request) {
    let {credential, options: {realm, scopes}} = request

    try {
      credential.validateScope(scopes)
    } catch (err) {
      return request.forbidden({
        realm,
        error: err.error,
        error_description: err.error_description
      })
    }

    return request
  }

  /**
   * success
   *
   * @description
   * Pass control to the next middleware.
   *
   * @param {AuthenticatedRequest} request
   */
  success (request) {
    let {req, credential, options} = request
    let {tokenProperty, claimsProperty} = options

    if (credential) {
      req[claimsProperty || 'claims'] = credential.claims
    }

    if (credential && tokenProperty) {
      req[tokenProperty] = credential.jwt
    }

    request.next()
  }

  /**
   * 400 Bad Request
   *
   * @description
   * Respond with 400 status code.
   *
   * @param {string} description
   */
  badRequest (description) {
    let {res, next, options} = this

    let params = {
      error: 'invalid_request',
      error_description: description
    }

    res.status(400)

    let error = new BadRequestError(params)

    // pass error
    if (options.handleErrors === false) {
      next(error)
    // respond
    } else {
      res.json(params)
    }

    throw error
  }

  /**
   * 401 Unauthorized
   *
   * @description
   * Respond with 401 status code and WWW-Authenticate challenge.
   *
   * @param {Object} params
   */
  unauthorized (params = {}) {
    const {res, next, options} = this

    res.set({
      'WWW-Authenticate': `Bearer ${this.encodeChallengeParams(params)}`
    })

    res.status(401)

    const error = new UnauthorizedError(params)

    // pass error
    if (options.handleErrors === false) {
      next(error)
    // respond
    } else {
      res.send('Unauthorized')
    }

    throw error
  }

  /**
   * 403 Forbidden
   *
   * @description
   * Respond with 403 status code and WWW-Authenticate challenge.
   *
   * @param {Object} params
   */
  forbidden (params = {}) {
    let {res, next, options} = this

    res.set({
      'WWW-Authenticate': `Bearer ${this.encodeChallengeParams(params)}`
    })

    res.status(403)

    let error = new ForbiddenError(params)

    // pass error
    if (options.handleErrors === false) {
      next(error)
    // respond
    } else {
      res.send('Forbidden')
    }

    throw error
  }

  /**
   * Serves as a general purpose error handler for `.catch()` clauses in
   * Promise chains. Example usage:
   *
   *   ```
   *   return Promise.resolve(request)
   *     .then(request.validate)
   *     .then(request.stepOne)
   *     .then(request.stepTwo)  // etc.
   *     .catch(request.error.bind(request))
   *   ```
   *
   * @param error {Error}
   */
  error (error) {
    // console.log('In rs.error():', error)

    if (!error.handled) {
      this.internalServerError(error)
    }
  }

  /**
   * 500 Internal Server Error
   *
   * @description
   * Respond with 500 status code.
   *
   * @param {Error} error
   */
  internalServerError (error) {
    let {res, next, options} = this

    if (options.handleErrors === false) {
      next(error)
    } else {
      res.status(500).send('Internal Server Error')
    }
  }

  /**
   * encodeChallengeParams
   *
   * @description
   * Encode parameters for WWW-Authenticate challenge header.
   *
   * @param {Object} params
   *
   * @return {string}
   */
  encodeChallengeParams (params) {
    let pairs = []

    for (let key in params) {
      pairs.push(`${key}="${params[key]}"`)
    }

    return pairs.join(', ')
  }

}

/**
 * Export
 */
module.exports = AuthenticatedRequest
