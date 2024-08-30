const mongoose = require('mongoose')

const { eStatus } = require('../enums')

const UserSchema = new mongoose.Schema({
  sEmail: { type: String },
  eStatus: { type: String, enum: eStatus.value, default: eStatus.default },
  sPassword: { type: String },
  aTokens: [{ sToken: String, sPushToken: String }]
}, { timestamps: { createdAt: 'dCreatedAt', updatedAt: 'dUpdatedAt' } })

module.exports = mongoose.model('user', UserSchema)
