const fastifyPlugin = require('fastify-plugin')

module.exports = fastifyPlugin(async(fastify) => {
  fastify.addHook('preHandler', async(request, reply) => {
    if (request.headers['accept-language']) {
      const lang = request.headers['accept-language']
      if (lang === 'en-US') {
        request.uLang = 'Eng'
      } else {
        request.uLang = 'Eng'
      }
    } else {
      request.uLang = 'Eng'
    }
  })
})
