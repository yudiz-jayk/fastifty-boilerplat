'use strict'
// require external modules
require('dotenv').config()
const path = require('path')
const fastify = require('fastify')({ logger: process.env.NODE_ENV !== 'prod', trustProxy: true })
const autoLoad = require('@fastify/autoload')
const helmet = require('@fastify/helmet')
const config = require('./config')
const { messages } = require('./lang/messages')

fastify.register(helmet, { contentSecurityPolicy: false })

// register custom plugins
fastify.register(autoLoad, {
  dir: path.join(__dirname, 'plugins')
})

fastify.decorate('conf', config)

fastify.setErrorHandler((error, request, reply) => {
  const userLanguage = request.uLang

  let sMessage = ''

  if (error.sMessageName) sMessage = messages[userLanguage]?.[error.sMessageName]?.message
  if (error.prefix) sMessage = sMessage?.replace('##', messages[userLanguage][error.prefix])

  const statusCode = messages[userLanguage]?.[error.sMessageName]?.status || 500
  if (sMessage === '') sMessage = error.message

  return reply.code(statusCode).send({ error: { sMessage, data: error.data } })
})

// start server
fastify.listen({ port: fastify.conf.PORT || 3000, host: '0.0.0.0' }, err => {
  if (err) {
    fastify.log.error(err)
    process.exit(1)
  }
  console.log(`Server is running on port ${process.env.PORT} 🚀`)
})
