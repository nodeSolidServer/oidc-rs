'use strict'

const AccessToken = require('./AccessToken')
const PoPToken = require('./PoPToken')
const DPoPToken = require('./DPoPToken')

class Credential {
  /**
   * @param jwt {JWT}
   *
   * @throws {DataError} If decoding an invalid access token (inside PoPToken)
   */
  static from (jwt, request) {
    if (jwt.payload && jwt.payload.token_type === 'pop') {
      return new PoPToken(jwt)
    } else if (request && request.tokenType === 'dpop') {
      return new DPoPToken(
        jwt,
        request.req.headers.dpop,
        request.options.realm,
        request.req
      )
    } else {
      return new AccessToken(jwt)
    }
  }
}

module.exports = Credential
