const prod = {
  DB_URL: process.env.DB_URL
}

const dev = {
  DB_URL: process.env.DB_URL
}

const stag = {
  DB_URL: process.env.DB_URL
}

let exportEnv = {}

switch (process.env.NODE_ENV) {
  case 'development':
    exportEnv = dev
    break
  case 'production':
    exportEnv = prod
    break
  case 'stag':
    exportEnv = stag
    break
  default:
    exportEnv = dev
    break
}

module.exports = exportEnv
