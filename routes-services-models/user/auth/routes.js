const { register, login } = require('./services')
const { userRegSchema, userLoginSchema } = require('./schema')

const { validateTimeZone } = require('../bookings/middleware')

module.exports = function (fastify, opts, done) {
  fastify.post('/register', { schema: userRegSchema, preHandler: [validateTimeZone] }, register)
  fastify.post('/login', { schema: userLoginSchema }, login)
  done()
}
