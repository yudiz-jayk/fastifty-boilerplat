const fastifyPlugin = require('fastify-plugin')
const cors = require('@fastify/cors')

module.exports = fastifyPlugin(async(fastify) => {
  fastify.register(cors)

  await fastify.register(require('@fastify/swagger'))

  await fastify.register(require('@fastify/swagger-ui'), {
    routePrefix: '/documentation',
    uiConfig: {
      docExpansion: 'none'
    },
    staticCSP: false
  })

  fastify.register(require('@fastify/formbody'))
})
