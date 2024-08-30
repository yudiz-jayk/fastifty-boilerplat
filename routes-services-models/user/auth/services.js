const config = require('../../../../config')
const { _, mailService } = require('../../../../utils')
const { redisClient } = require('../../../../utils/lib/redis')
const { cuMembersModel, cmClubsModel, cuClubMembersModel } = require('../../../clubMatch-admin/models')
const { cuVerificationModel, cuAvailabilitiesModel } = require('../../models')
const moment = require('moment-timezone')
const { cleanBookingStuff } = require('../common/services')
const { CaRolesModel } = require('../../../clubMatch-club-admin/models')

async function register(request, reply) {
  try {
    const { sEmail, sClubMatchId, aClubs, sFirstName, sLastName, eGender, dDob, sPhone, sPassword, sCode, sPushToken } = request.body

    const isValidated = await validateMemberForSignupFunc({ sEmail, sClubMatchId, aClubs })

    if (isValidated.message !== 'memberValidated') return _.sendResponse({ reply, message: 'wentWrong', uLang: request.uLang })

    const exist = await cuVerificationModel.findOne({ sLogin: sEmail, eType: 'e', eAuth: 'r', sCode, bIsVerify: true }).sort({ dCreatedAt: -1 })
    if (!exist) return _.sendResponse({ reply, title: 'tryAgain', message: 'invalidCode', uLang: request.uLang })

    const checkReg = await cuMembersModel.findOne({ sEmail, eStatus: 'a' }).lean()
    if (checkReg && checkReg.bIsRegistered) throw new _.APIError({ message: 'memberAlreadyExistsErr' })

    let member = {}
    if (sClubMatchId) {
      member = await cuMembersModel.findOneAndUpdate({ sEmail, sClubMatchId }, { sFirstName, sEmail, sLastName, eGender, dDob, sPhone, sPassword: _.encryptPassword(sPassword), bTempPassword: false }, { upsert: true, new: true })
    } else {
      const clubmatchId = _.generateRandomId(6, 'ALPHANUMERIC')
      member = await cuMembersModel.create({ sClubMatchId: clubmatchId, sFirstName, sLastName, sEmail, eGender, dDob, sPhone, sPassword: _.encryptPassword(sPassword), bTempPassword: false, sTimeZone: request.sTimeZone, bIsRegistered: true })
    }

    const newToken = {
      sToken: _.encodeToken({ iClubUserId: (member._id).toString() }, config.CU_JWT_VALIDITY),
      sPushToken
    }

    if (!member?.aTokens) {
      member.aTokens = [newToken]
    } else {
      if (member.aTokens.length < config.CU_LOGIN_LIMIT) member.aTokens.push(newToken)
      else {
        member.aTokens.splice(0, 1)
        member.aTokens.push(newToken)
      }
    }

    member = JSON.parse(JSON.stringify(await member.save()))
    member.sToken = newToken.sToken

    const aClubsData = isValidated?.data?.aClubs

    for (const club of aClubsData) {
      await cuClubMembersModel.updateOne({ iClubId: club._id, iMemberId: member._id }, { iClubId: club._id, iMemberId: member._id, eType: sClubMatchId ? 'm' : 'g' }, { upsert: true })
    }

    exist.bIsVerify = true
    await exist.save()
    return _.sendResponse({ reply, message: 'registeredSuccess', prefix: 'member', data: { oMember: member }, uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    if (error.code === 11000 && error.keyPattern?.sEmail) throw new _.APIError({ message: 'already_exist', prefix: 'email' })
    throw new _.APIError({ reply, message: 'wentWrong', uLang: request.uLang })
  }
}

async function registerAvailability(request, reply) {
  try {
    const { sAvatar, eTennisLevel, aWeeklyAvailability, bIsDiscoverable, bIsOpenToAllInvites, bIsOpenToCoaching } = request.body

    const member = await cuMembersModel.findByIdAndUpdate(request.decodeToken.iClubUserId, { sAvatar, eTennisLevel, nLevelScore: _.levelScoreMapping[eTennisLevel] }, { new: true })
    if (!member) throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })

    const availability = await cuAvailabilitiesModel.findOneAndUpdate({ iMemberId: member._id }, { aWeeklyAvailability, bIsDiscoverable, bIsOpenToAllInvites, bIsOpenToCoaching }, { upsert: true, new: true })

    return _.sendResponse({ reply, message: 'add_success', prefix: 'availability', data: { oAvailability: availability }, uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong' })
  }
}

async function login(request, reply) {
  const { sEmail, sPassword, sPushToken } = request.body

  const user = await cuMembersModel.findOne({ sEmail, eStatus: 'a' }, { sEmail: 1, sPassword: 1, aTokens: 1 })
  if (!user) throw new _.APIError({ reply, message: 'invalidCred', uLang: request.uLang })

  if (user.sPassword !== _.encryptPassword(sPassword)) {
    const { isLimitReached } = await _.apiRateLimiter({ ip: request.ip, path: 'user-login', threshold: _.constrains.loginThreshold, time: _.constrains.loginRateLimit })
    if (isLimitReached) throw new _.APIError({ message: 'toManyRequestErr' })
    throw new _.APIError({ message: 'invalidCred' })
  }

  const newToken = {
    sToken: _.encodeToken({ iClubUserId: (user._id).toString() }, config.CU_JWT_VALIDITY),
    sPushToken
  }

  if (!user?.aTokens) {
    user.aTokens = [newToken]
  } else {
    if (user.aTokens.length < config.CU_LOGIN_LIMIT) user.aTokens.push(newToken)
    else {
      const ele = user.aTokens.splice(0, 1)
      const decodedToken = _.decodeToken(ele.sToken)
      if (decodedToken?.exp) await redisClient.setex(`trashToken:${ele.sToken}`, moment(decodedToken.exp * 1000).diff(moment(), 'seconds'), user._id)
      user.aTokens.push(newToken)
    }
  }

  cuMembersModel.updateOne({ _id: _.mongify(user._id) }, { $set: { aTokens: user.aTokens, nLastLoginDate: moment.utc().valueOf() } }).then().catch(err => console.log(err))

  return _.sendResponse({ reply, message: 'success', prefix: 'login', data: { sToken: newToken.sToken }, uLang: request.uLang })
}

async function forgotPassword(request, reply) {
  const { sEmail } = request.body

  const user = await cuMembersModel.findOne({ sEmail }, { _id: 1 }).lean()
  if (!user) throw new _.APIError({ message: 'accountNotExist' })

  const { isLimitReached } = await _.apiRateLimiter({ ip: request.ip, path: 'user-forgotpassword', threshold: _.constrains.forgotPasswordThreshold, time: _.constrains.forgotPasswordRateLimit })
  if (isLimitReached) throw new _.APIError({ message: 'toManyRequestErr' })

  const sForgotPasswordToken = _.encodeToken({ iClubUserId: user._id }, '1h')

  await cuMembersModel.updateOne({ _id: _.mongify(user._id) }, { $set: { sForgotPasswordToken } })

  // mailService.sendMail({
  //   from: config.SMTP_USER,
  //   to: user.sEmail,
  //   subject: 'Forgot Password',
  //   html: `<!DOCTYPE html>
  //   <html lang="en">
  //   <head>
  //     <meta charset="UTF-8">
  //     <meta name="viewport" content="width=device-width, initial-scale=1.0">
  //     <title>Reset your password</title>
  //     <style>
  //       body {
  //         font-family: sans-serif;
  //       }

  //       h1 {
  //         font-size: 24px;
  //         font-weight: bold;
  //         margin-top: 0;
  //       }

  //       p {
  //         font-size: 16px;
  //         line-height: 1.5em;
  //       }

  //       a {
  //         color: #000;
  //         text-decoration: none;
  //       }

  //       a:hover {
  //         text-decoration: underline;
  //       }
  //     </style>
  //   </head>
  //   <body>
  //     <h1>Reset your password</h1>
  //     <p>Click on the following link to reset your password:</p>
  //     <a href="${config.USER_FRONT_URL}/reset-password?${sForgotPasswordToken}">Reset password</a>
  //     <p>If you don't click on the link within 24 hours, it will expire.</p>
  //   </body>
  //   </html>`
  // }).then().catch(err => console.log(err))

  return _.sendResponse({ reply, message: 'forgotPassLink', prefix: null, data: null, uLang: request.uLang })
}

async function resetPassword(request, reply) {
  const { sLogin, sCode, sPassword } = request.body

  let aToken = []

  const d = new Date()

  d.setSeconds(d.getSeconds() - config.CU_OTP_RESEND_TIME)
  const exist = await cuVerificationModel.findOne({ sLogin, eType: 'e', eAuth: 'f', dExpiredAt: { $gt: d }, sCode, bIsVerify: true }).sort({ dCreatedAt: -1 }).lean()

  if (!exist) throw new _.APIError({ reply, message: 'invalidCode', uLang: request.uLang })

  // if (exist && +new Date(exist.dExpiredAt) > +d) return _.sendResponse({ reply, message: 'invalidCode', uLang: request.uLang })

  if (_.isPassword(sPassword)) throw new _.APIError({ message: 'invalidPassword' })

  const user = await cuMembersModel.findOne({ sEmail: sLogin, eStatus: 'a' }).lean()
  if (!user) throw new _.APIError({ message: 'accountNotExist' })

  if (user?.aTokens?.length) aToken = [...user?.aTokens]

  if (user?.aTokens?.length) {
    aToken = user?.aTokens
    for (let index = 0; index < aToken.length; index++) {
      const ele = user.aTokens[index]
      if (ele.sToken) {
        const decodedToken = _.decodeToken(ele.sToken)
        if (decodedToken?.exp) await redisClient.setex(`trashToken:${ele.sToken}`, moment(decodedToken.exp * 1000).diff(moment(), 'seconds'), user._id)
        else aToken.splice(index, 1)
      }
    }
  }

  const akg = await cuMembersModel.updateOne({ _id: user._id }, { $set: { aTokens: aToken }, sPassword: _.encryptPassword(sPassword) })
  if (!akg.modifiedCount) throw new _.APIError('wentWrong')

  return _.sendResponse({ reply, message: 'passReset', prefix: null, data: null, uLang: request.uLang })
}

async function logout(request, reply) {
  const { iClubUserId, exp } = request.decodeToken

  await cuMembersModel.updateOne({ _id: iClubUserId, 'aTokens.sToken': request.headers.authorization }, { $pull: { aTokens: { sToken: request.headers.authorization } } })
  if (exp) await redisClient.setex(`trashToken:${request.headers.authorization}`, moment(exp * 1000).diff(moment(), 'seconds'), `${iClubUserId}`)

  return _.sendResponse({ reply, message: 'success', prefix: 'logout', uLang: request.uLang })
}

async function validateMemberForSignup(request, reply) {
  try {
    const { sEmail, sClubMatchId, aClubs } = request.body
    const result = await validateMemberForSignupFunc({ sEmail, sClubMatchId, aClubs })

    switch (result.message) {
      case 'no_club_found':
        return _.sendResponse({ reply, message: 'required', prefix: 'club', uLang: request.uLang })
      case 'membershipNotRecognised':
        return _.sendResponse({ reply, title: 'not_recognized', message: 'membershipNotRecognised', uLang: request.uLang })
      case 'memberOnlyClub':
        return _.sendResponse({ reply, title: 'member_only', message: 'memberOnlyClub', data: result.data, uLang: request.uLang })
      case 'not_guest':
        return _.sendResponse({ reply, title: 'not_guest', message: 'notGuestErr', data: result.data, uLang: request.uLang })
      case 'memberValidated':
        return _.sendResponse({ reply, message: 'success', prefix: 'member_validate', data: result.data, uLang: request.uLang })
      default:
        return _.sendResponse({ reply, message: 'wentWrong' })
    }
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong' })
  }
}

async function sendOtp(request, reply) {
  try {
    const { sLogin, eType, eAuth } = request.body
    let member = await cuMembersModel.findOne({ sEmail: sLogin, eStatus: 'a' })

    if (eAuth === 'r' || eAuth === 'f') {
      if (member && member.eTennisLevel && eAuth === 'r') return _.sendResponse({ reply, message: 'already_exist', prefix: 'email', uLang: request.uLang })

      if (!member && eAuth === 'f') return _.sendResponse({ reply, message: 'accountNotExist', uLang: request.uLang })
    }

    if (eAuth === 'v') {
      if (!request.header('Authorization')) return _.sendResponse({ reply, message: 'authorizationError', uLang: request.uLang })

      member = await cuMembersModel.findByToken(request.header('Authorization'))
      if (!member) return _.sendResponse({ reply, message: 'authorizationError', uLang: request.uLang })
    }

    const d = new Date()
    d.setSeconds(d.getSeconds() - config.CU_OTP_RESEND_TIME)
    const exist = await cuVerificationModel.findOne({ sLogin, eType, eAuth, dUpdatedAt: { $gt: d } }).sort({ dCreatedAt: -1 }).lean()

    if (exist && +new Date(exist.dUpdatedAt) > +d) return _.sendResponse({ reply, message: 'err_resend_otp', prefix: 'ThirtySec', uLang: request.uLang })

    const rateLimit = await _.checkRateLimitOTP(sLogin, eType, eAuth)
    if (rateLimit === 'LIMIT_REACHED') return _.sendResponse({ reply, message: 'limit_reached', prefix: 'OTP', uLang: request.uLang })

    let sCode = null

    if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'stag') {
      sCode = '1111'
    } else if (process.env.NODE_ENV === 'production') {
      sCode = _.generateRandomId(4, 'NUMBER')
    }

    const codeValidity = new Date()
    codeValidity.setSeconds(codeValidity.getSeconds() + config.CU_OTP_EXPIRY_TIME)
    await cuVerificationModel.findOneAndUpdate({ sLogin, eType, eAuth }, { sLogin, eType, eAuth, sCode, bIsVerify: false, dExpiredAt: codeValidity }, { upsert: true })

    if (eType === 'e') {
      // mailService.sendMail({
      //   from: config.SMTP_USER,
      //   to: member.sEmail,
      //   subject: 'Forgot Password',
      //   html: mailTemplates({ eType: 'forgotPass', otp: sCode })
      // }).then().catch(err => console.log(err))

      // console.log(mailTemplates({ eType: 'forgotPass', otp: sCode }))
    }
    if (eType === 'm') {
      console.log('m')
      // await sendSMS(sLogin, sCode)
    }

    return _.sendResponse({ reply, message: 'sent_success', prefix: 'OTP', uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong' })
  }
}

async function verifyOTP(request, reply) {
  try {
    const { sLogin, eType = 'e', eAuth, sCode } = request.body

    const d = new Date()

    const exist = await cuVerificationModel.findOne({ sLogin, eType, eAuth, sCode, bIsVerify: false }).sort({ dCreatedAt: -1 }).limit(1)
    if (!exist || exist.sCode !== sCode) return _.sendResponse({ reply, message: 'invalidCode', uLang: request.uLang })

    if (exist && +new Date(exist.dExpiredAt) < +d) return _.sendResponse({ reply, message: 'otpExpireErr', uLang: request.uLang })

    exist.bIsVerify = true
    await exist.save()

    return _.sendResponse({ reply, message: 'verifySuccess', prefix: 'OTP', uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong' })
  }
}

async function changePassword(request, reply) {
  try {
    const { sOldPassword, sNewPassword, sConfirmPassword } = request.body
    const user = await cuMembersModel.findById(request.decodeToken.iClubUserId, { sPassword: 1 })

    if (user.sPassword !== _.encryptPassword(sOldPassword)) return _.sendResponse({ reply, message: 'invalidCred', uLang: request.uLang })

    if (sNewPassword !== sConfirmPassword) return _.sendResponse({ reply, message: 'passAndCpassNotMatch', uLang: request.uLang })

    if (_.isPassword(sNewPassword)) return _.sendResponse({ reply, message: 'invalidPassword', uLang: request.uLang })

    await cuMembersModel.updateOne({ _id: request.decodeToken.iClubUserId }, { sPassword: _.encryptPassword(sNewPassword) })

    return _.sendResponse({ reply, message: 'success', prefix: 'passwordChanged', uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

async function updateProfile(request, reply) {
  try {
    const { sFirstName, sLastName, sPhone, dDob, eGender, sAvatar } = request.body
    const member = await cuMembersModel.findByIdAndUpdate(request.decodeToken.iClubUserId, { sFirstName, sLastName, sPhone, dDob, eGender, sAvatar }, { new: true })

    if (!member) throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })

    return _.sendResponse({ reply, message: 'editSuccess', prefix: 'profile', uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

async function updateAvailability(request, reply) {
  try {
    const { bIsDiscoverable, bIsOpenToAllInvites, bIsOpenToCoaching, aWeeklyAvailability } = request.body
    await cuAvailabilitiesModel.findOneAndUpdate({ iMemberId: request.decodeToken.iClubUserId }, { bIsDiscoverable, bIsOpenToAllInvites, bIsOpenToCoaching, aWeeklyAvailability }, { upsert: true, new: true })

    return _.sendResponse({ reply, message: 'editSuccess', prefix: 'availability', uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

async function incidentReport(request, reply) {
  try {
    const { sText } = request.body
    const { iClubId } = request.params

    const roles = await CaRolesModel.find({ eRole: { $in: ['wfo', 'sa'] } }, { _id: 1, eRole: 1 }).lean()

    const wfoRole = roles.find(role => role.eRole === 'wfo')
    const saRole = roles.find(role => role.eRole === 'sa')

    const selectedRole = wfoRole || saRole

    if (!selectedRole) {
      throw new _.APIError({ message: 'wentWrong' })
    }

    const clubAdmin = await cuClubMembersModel.find({
      iClubId,
      isAdministrator: true,
      aAdministerRoleId: _.mongify(selectedRole._id)
    })

    const aEmails = clubAdmin.map(admin => admin.oMember.sEmail)

    mailService.sendMail({
      from: config.SMTP_USER,
      to: aEmails,
      subject: 'Incident Report',
      html: `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Incident Report</title>
        <style>
          body {
            font-family: sans-serif;
          }
      
          h1 {
            font-size: 24px;
            font-weight: bold;
            margin-top: 0;
          }
      
          p {
            font-size: 16px;
            line-height: 1.5em;
          }
      
          a {
            color: #000;
            text-decoration: none;
          }
      
          a:hover {
            text-decoration: underline;
          }
        </style>
      </head>
      <body>
        <h1>Incident Report</h1>
        <p>${sText}</p>
      </body>
      </html>`
    }).then().catch(err => console.log(err))

    return _.sendResponse({ reply, message: 'sent_success', prefix: 'incidentReport', uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

async function listTennisLevels(request, reply) {
  try {
    return _.sendResponse({
      reply,
      message: 'fetch_success',
      prefix: 'tennisLevel',
      data: {
        aTennisLevels: [
          {
            sGroup: 'Beginner',
            aLevels: [{ sTitle: '1', sValue: 'BEG1' }, { sTitle: '2', sValue: 'BEG2' }, { sTitle: '3', sValue: 'BEG3' }]
          },
          {
            sGroup: 'Improver',
            aLevels: [{ sTitle: '1', sValue: 'IMP1' }, { sTitle: '2', sValue: 'IMP2' }, { sTitle: '3', sValue: 'IMP3' }, { sTitle: '4', sValue: 'IMP4' }]
          },
          {
            sGroup: 'Intermediate',
            aLevels: [{ sTitle: '1', sValue: 'INT1' }, { sTitle: '2', sValue: 'INT2' }, { sTitle: '3', sValue: 'INT3' }, { sTitle: '4', sValue: 'INT4' }, { sTitle: '5', sValue: 'INT5' }, { sTitle: '6', sValue: 'INT6' }]
          },
          {
            sGroup: 'Advanced',
            aLevels: [{ sTitle: '1', sValue: 'ADV1' }, { sTitle: '2', sValue: 'ADV2' }, { sTitle: '3', sValue: 'ADV3' }]
          }
        ]
      },
      uLang: request.uLang
    })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

async function listAvatar(request, reply) {
  try {
    const aAvatar = []
    for (let index = 1; index <= 16; index++) {
      const sAvatar = `/Avatar/avatar-${index}.png`
      aAvatar.push(sAvatar)
    }

    return _.sendResponse({ reply, message: 'fetch_success', prefix: 'avatar', data: { aAvatar }, uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

async function updateClubInProfile(request, reply) {
  try {
    const { aClubs } = request.body
    const { iClubUserId } = request.decodeToken

    // Fetch all clubs (member and guest) for the user
    const userClubs = await cuClubMembersModel.find({ iMemberId: iClubUserId, eStatus: 'a' }).lean()

    // Separate member and guest club IDs
    const memberClubIds = userClubs
      .filter(club => ['m'].includes(club.eType))
      .map(club => club.iClubId.toString())

    const guestClubIds = userClubs
      .filter(club => club.eType === 'g')
      .map(club => club.iClubId.toString())

    // Convert aClubs to a Set for faster lookups
    const aClubsSet = new Set(aClubs)

    // Check if every element of memberClubIds is present in aClubsSet
    const allMemberClubsPresent = memberClubIds.every(id => aClubsSet.has(id))

    if (!allMemberClubsPresent) {
      throw new _.APIError({ message: 'wentWrong' })
    }

    const memberClubIdsSet = new Set(memberClubIds)

    const guestsClub = aClubs.filter(id => !memberClubIdsSet.has(id))

    // Fetch clubs from database
    const clubs = await cmClubsModel.find({ _id: { $in: guestsClub } }).lean()

    const memberOnlyClub = []
    for (const club of clubs) {
      if (!club.oClubBookingRules?.bIsGuestAllowed) {
        const clubMember = await cuClubMembersModel.findOne({ iMemberId: iClubUserId, iClubId: club._id, eType: 'm' })
        if (!clubMember) memberOnlyClub.push(club.sName)
      }
    }

    if (memberOnlyClub.length) {
      return _.sendResponse({ reply, title: 'member_only', message: 'memberOnlyClub', data: { aMemberOnlyClub: memberOnlyClub }, uLang: request.uLang })
    }

    // Add or update guest clubs
    for (const club of clubs) {
      await cuClubMembersModel.updateOne({ iClubId: club._id, iMemberId: iClubUserId }, { iClubId: club._id, iMemberId: iClubUserId, eType: 'g', eStatus: 'a' }, { upsert: true })
    }

    // Identify guest clubs to deactivate
    const guestClubsToDeactivate = guestClubIds.filter(id => !aClubsSet.has(id))

    // Update status of deactivated guest clubs
    for (const clubId of guestClubsToDeactivate) {
      await cuClubMembersModel.updateOne({ iClubId: clubId, iMemberId: iClubUserId }, { eStatus: 'd' })
    }

    return _.sendResponse({ reply, message: 'editSuccess', prefix: 'club', uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

async function listMembersClub(request, reply) {
  const query = { iMemberId: _.mongify(request.decodeToken.iClubUserId), eStatus: 'a' }

  if (request?.query?.aRoleType?.length) {
    Object.assign(query, { eType: { $in: request.query.aRoleType } })
  }

  if (request.query.aSubRoleType) {
    Object.assign(query, { eClubMemberSubType: { $in: request.query.aSubRoleType } })
  }

  try {
    const membersClub = await cuClubMembersModel.aggregate([
      {
        $match: query
      },
      {
        $lookup: {
          from: 'cm_clubs',
          localField: 'iClubId',
          foreignField: '_id',
          as: 'oClub'
        }
      },
      {
        $project: {
          eType: '$eType',
          _id: '$oClub._id',
          sName: '$oClub.sName',
          eClubMemberSubType: '$eClubMemberSubType'
        }
      }
    ])

    return _.sendResponse({ reply, message: 'fetch_success', prefix: 'members_clubs', data: { aMembersClubs: membersClub }, uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

async function fetchMembersClub(request, reply) {
  try {
    const { sClubMatchId, sEmail } = request.body

    const member = await cuMembersModel.findOne({ sEmail, sClubMatchId })
    if (!member) return _.sendResponse({ reply, title: 'not_recognized', message: 'membershipNotRecognised', uLang: request.uLang })
    else if (member && member.bIsRegistered) return _.sendResponse({ reply, title: 'memberAlreadyExists', message: 'memberAlreadyRegisterErr', uLang: request.uLang })

    const membersClub = await cuClubMembersModel.aggregate([
      {
        $match: { iMemberId: member._id, eType: { $ne: 'g' }, eStatus: 'a' }
      },
      {
        $lookup: {
          from: 'cm_clubs',
          localField: 'iClubId',
          foreignField: '_id',
          as: 'oClub'
        }
      },
      {
        $project: {
          _id: '$oClub._id',
          sName: '$oClub.sName'

        }
      }
    ])

    return _.sendResponse({ reply, message: 'fetch_success', prefix: 'members_clubs', data: { aMembersClubs: membersClub }, uLang: request.uLang })
  } catch (error) {
    console.log({ error })
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

const validateMemberForSignupFunc = async(req) => {
  const { sEmail, sClubMatchId, aClubs } = req

  return new Promise((resolve, reject) => {
    try {
      (async function() {
        const clubs = await cmClubsModel.find({ _id: { $in: aClubs } }).lean()
        if (!clubs.length) return resolve({ message: 'no_club_found' })

        const member = await cuMembersModel.findOne({ sEmail })
        if (sEmail && sClubMatchId) {
          if ((!member) || (member && sClubMatchId && member.sClubMatchId !== sClubMatchId)) return resolve({ message: 'membershipNotRecognised' })
        } else if (sEmail && !sClubMatchId) {
          const isAnyClubsMember = await cuClubMembersModel.findOne({ iMemberId: member?._id, eType: 'm', eStatus: 'a' })
          if (isAnyClubsMember) return resolve({ message: 'not_guest' })
        }

        const memberOnlyClub = []
        for (const club of clubs) {
          if (!club.oClubBookingRules?.bIsGuestAllowed) {
            const clubMember = await cuClubMembersModel.findOne({ iMemberId: member?._id, iClubId: club._id, eType: 'm' })
            if (!clubMember) memberOnlyClub.push(club.sName)
          }
        }

        if (memberOnlyClub.length) {
          return resolve({ message: 'memberOnlyClub', data: { aMemberOnlyClub: memberOnlyClub } })
        } else {
          return resolve({ message: 'memberValidated', data: { oMember: member, aClubs: clubs } })
        }
      })()
    } catch (error) {
      console.log({ error })
      return reject(error)
    }
  })
}

const listClubs = async(request, reply) => {
  try {
    const { sSearch } = request.query
    const clubs = await cmClubsModel.find({ eStatus: 'a', $or: [{ sName: new RegExp(sSearch, 'i') }, { sCounty: new RegExp(sSearch, 'i') }] }, { sName: 1, sCounty: 1, 'oClubBookingRules.bIsGuestAllowed': 1 }).lean()
    return _.sendResponse({ reply, message: 'fetch_success', prefix: 'club_list', data: { aClubs: clubs }, uLang: request.uLang })
  } catch (error) {
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

const getProfile = async(request, reply) => {
  try {
    const data = await cuMembersModel.findById(request.decodeToken.iClubUserId).populate([{ path: 'oAvailabilities' }]).lean()
    if (!data) throw new _.APIError({ message: 'NotFound', prefix: 'member' })

    const isAdmin = await cuClubMembersModel.findOne({ iMemberId: request.decodeToken.iClubUserId, isAdministrator: true, eStatus: 'a' }, { _id: 1 }).lean()
    if (isAdmin) Object.assign(data, { isAdmin: !!isAdmin })

    return _.sendResponse({ reply, message: 'fetch_success', prefix: 'profile', data, uLang: request.uLang })
  } catch (error) {
    throw new _.APIError({ message: 'wentWrong', uLang: request.uLang, reply })
  }
}

async function getLevelInfo(request, reply) {
  const member = await cuMembersModel.findById(request.decodeToken.iClubUserId, { eTennisLevel: 1, nLevelScore: 1 }).lean()

  if (!member) {
    throw new _.APIError({ message: 'NotFound', prefix: 'member' })
  }

  const { eTennisLevel, nLevelScore } = member
  const currentLevel = eTennisLevel

  const levels = Object.keys(_.levelScoreMapping)
  const currentLevelIndex = levels.indexOf(eTennisLevel)

  const nextLevel = levels[currentLevelIndex + 1]
  const prevLevel = currentLevelIndex > 0 ? levels[currentLevelIndex - 1] : null

  const data = {

    oCurrentLevel: {
      sLevel: eTennisLevel,
      nPoint: nLevelScore
    },
    oNextLevel: nextLevel
      ? {
          sLevel: nextLevel,
          nPointReq: _.levelScoreMapping[nextLevel] - nLevelScore
        }
      : null,
    oPrevLevel: prevLevel
      ? {
          sLevel: prevLevel,
          nPointReq: nLevelScore - (_.levelScoreMapping[currentLevel] - 1)
        }
      : null
  }

  return _.sendResponse({ reply, message: 'fetch_success', prefix: 'level', data, uLang: request.uLang })
}

async function getUserPermissions(request, reply) {
  const { iClubUserId } = request.decodeToken
  const { iClubId } = request.query

  // Find the club member details
  const clubMember = await cuClubMembersModel.findOne({ iMemberId: iClubUserId, iClubId })
    .populate('oMember')
    .populate({
      path: 'aAdministerRoleId',
      model: 'ca_roles',
      select: 'eRole sName aAllowedSec'
    })
    .lean()

  if (!clubMember) {
    throw new _.APIError({ message: 'NotFound', prefix: 'member' })
  }

  const { isAdministrator, aAdministerRoleId } = clubMember
  let aRoles = aAdministerRoleId

  const isSuperAdmin = aRoles.some(role => role.eRole === 'sa')
  if (isSuperAdmin) {
    aRoles = await CaRolesModel.find({ eStatus: 'a' }, { eRole: 1, aAllowedSec: 1 }).lean()
  }

  // Combine the allowed sections from all roles
  const aAllowedSections = aRoles.reduce((acc, role) => {
    return [...acc, ...role.aAllowedSec]
  }, [])

  const data = {
    isAdministrator,
    aRoles,
    aAllowedSections
  }

  return _.sendResponse({ reply, message: 'fetch_success', prefix: 'permission', data, uLang: request.uLang })
}

async function deleteAccount(request, reply) {
  const { iClubUserId } = request.decodeToken

  const member = await cuMembersModel.findOne({ _id: iClubUserId })
  if (!member) {
    throw new _.APIError({ message: 'NotFound', prefix: 'member' })
  }

  await cleanBookingStuff({ iMemberId: member._id })

  if (member?.aTokens?.length) {
    for (const token of member.aTokens) {
      const decodedToken = _.decodeToken(token.sToken)
      if (decodedToken?.exp) {
        const expirationTime = moment(decodedToken.exp * 1000).diff(moment(), 'seconds')
        await redisClient.setex(`trashToken:${token.sToken}`, expirationTime, member._id)
      }
    }

    member.aTokens = []
    await member.save()
  }

  // remove account from all clubs
  await cuClubMembersModel.updateMany({ iMemberId: iClubUserId }, { eStatus: 'd' })

  return _.sendResponse({ reply, message: 'delete_success', prefix: 'account', uLang: request.uLang })
}

async function updatePushNotificationSettings(request, reply) {
  const { bIsPushNotificationAllowed } = request.body
  const iMemberId = request.decodeToken.iClubUserId

  const updatedMember = await cuMembersModel.updateOne(
    { _id: iMemberId },
    { $set: { bIsPushNotificationAllowed } }
  )

  if (updatedMember.modifiedCount === 0) {
    throw new _.APIError({ message: 'wentWrong' })
  }

  return _.sendResponse({
    reply,
    message: 'editSuccess',
    prefix: 'pushNotificationSettings',
    data: { bIsPushNotificationAllowed },
    uLang: request.uLang
  })
}

module.exports = {
  register,
  login,
  forgotPassword,
  resetPassword,
  logout,
  validateMemberForSignup,
  sendOtp,
  verifyOTP,
  registerAvailability,
  changePassword,
  updateProfile,
  updateAvailability,
  incidentReport,
  listTennisLevels,
  listAvatar,
  updateClubInProfile,
  listMembersClub,
  fetchMembersClub,
  listClubs,
  getProfile,
  getLevelInfo,
  getUserPermissions,
  deleteAccount,
  updatePushNotificationSettings
}
