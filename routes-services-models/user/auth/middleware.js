const { _, redis: { redisClient } } = require('../../../../utils')

async function isClubUserAuthenticated (request, reply) {
  const { authorization } = request.headers

  if (!authorization) throw new _.APIError({ message: 'authorizationError' })

  if (await redisClient.get(`trashToken:${authorization}`)) {
    throw new _.APIError({ message: 'sessionExpiredErr' })
  }

  const decodedToken = _.decodeToken(authorization)

  if (!decodedToken || decodedToken === 'jwt expired' || !decodedToken?.iClubUserId || decodedToken === 'invalid signature' || decodedToken === 'jwt malformed') {
    throw new _.APIError({ message: 'authorizationError' })
  }

  request.decodeToken = decodedToken
}

module.exports = { isClubUserAuthenticated }
