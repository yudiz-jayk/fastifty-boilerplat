const fastifyPlugin = require('fastify-plugin')
const mongoose = require('mongoose')

module.exports = fastifyPlugin(async (fastify) => {
  try {
    const url = fastify.conf.DB_URL
    if (url) {
      await mongoose.connect(url)
      console.log(fastify.conf.DB_URL)
    } else {
      console.log('Error connecting database')
    }
  } catch (err) {
    console.log(err)
  }
})
mongoose.set('autoIndex', true)
mongoose.set('debug', false)
