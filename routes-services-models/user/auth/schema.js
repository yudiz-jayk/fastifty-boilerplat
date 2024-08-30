const S = require('fluent-json-schema')
const { errorResponseSchema, authenticationHeaderSchema, timeZoneHeaderSchema } = require('../../../clubMatch-admin/routes-services/common/schema')
const { eVerificationChannelType, eVerificationAuth, eWeekDays, eGender } = require('../../models/enums')
const { eTennisLevel, eClubMemberType, eAllowedSection, eClubMemberSubType } = require('../../../clubMatch-admin/models/enums')
const { eRole } = require('../../../clubMatch-club-admin/models/enums')

const tags = ['user/auth']

const userRegSchema = {
  tags,
  headers: S.object().allOf([timeZoneHeaderSchema]),
  body: S.object()
    .prop('sClubMatchId', S.string())
    .prop('sPushToken', S.string())
    .prop('sEmail', S.string().format(S.FORMATS.EMAIL).required())
    .prop('sFirstName', S.string().required())
    .prop('sLastName', S.string().required())
    .prop('eGender', S.string().required().enum(eGender.value))
    .prop('dDob', S.string().required())
    .prop('sPhone', S.string())
    .prop('sPassword', S.string().required().pattern(/^.{8,}$/))
    .prop('sCode', S.string().required())
    .prop('aClubs', S.array().items(S.string()).required()),
  response: {
    200: S.object()
      .prop('sMessage', S.string())
      .prop('data', S.object()
        .prop('oMember', S.object()
          .prop('sClubMatchId', S.string())
          .prop('sEmail', S.string())
          .prop('sFirstName', S.string())
          .prop('sLastName', S.string())
          .prop('sPhone', S.string())
          .prop('dDob', S.string())
          .prop('eGender', S.string())
          .prop('sToken', S.string())
        )
      ),
    '4xx': S.object()
      .prop('sMessage', S.string())
      .prop('sTitle', S.string()),
    '5xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }
}

const userLoginSchema = {
  tags,
  body:
    S.object()
      .prop('sEmail', S.string().format(S.FORMATS.EMAIL).required())
      .prop('sPushToken', S.string())
      .prop('sPassword', S.string().required()),
  response: {
    200: S.object()
      .prop('sMessage', S.string())
      .prop('data', S.object()
        .prop('sToken', S.string())
      ),
    default: errorResponseSchema
  }
}

const userForgotPassSchema = {
  tags,
  body: S.object()
    .prop('sEmail', S.string().format(S.FORMATS.EMAIL).required()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }
}

const userLogoutSchema = {
  tags,
  headers: authenticationHeaderSchema,
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    default: S.object()
      .prop('error', S.object()
        .prop('sMessage', S.string())
      )
  }
}

const userResetPasswordSchema = {
  tags,
  body: S.object()
    .prop('sLogin', S.string().required())
    .prop('sCode', S.string().required())
    .prop('sPassword', S.string().pattern(/^.{8,16}$/).required()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }

}

const validateMemberSchema = {
  tags,
  body: S.object()
    .prop('sEmail', S.string().format(S.FORMATS.EMAIL).required())
    .prop('sClubMatchId', S.string())
    .prop('aClubs', S.array().items(S.string())),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string())
      .prop('sTitle', S.string())
      .prop('data', S.object()
        .prop('oMember', S.object()
          .prop('sEmail', S.string())
          .prop('sFirstName', S.string())
          .prop('sLastName', S.string())
          .prop('sPhone', S.string())
          .prop('dDob', S.string())
          .prop('eGender', S.string())
        )
      ),
    '4xx': S.object()
      .prop('sMessage', S.string())
      .prop('sTitle', S.string())
      .prop('data', S.object()
        .prop('aMemberOnlyClub', S.array().items(S.string()))
      ),
    default: errorResponseSchema
  }
}

const sendOtpSchema = {
  tags,
  body: S.object()
    .prop('sLogin', S.string().format(S.FORMATS.EMAIL).required())
    .prop('eType', S.string().enum(eVerificationChannelType.value).required())
    .prop('eAuth', S.string().enum(eVerificationAuth.value).required()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    '4xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }
}

const verifyOtpSchema = {
  tags,
  body: S.object()
    .prop('sLogin', S.string().format(S.FORMATS.EMAIL).required())
    .prop('eType', S.string().enum(eVerificationChannelType.value).required())
    .prop('eAuth', S.string().enum(eVerificationAuth.value).required())
    .prop('sCode', S.string().required()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    '4xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }
}

const registerAvailabilitySchema = {
  tags,
  headers: authenticationHeaderSchema,
  body: S.object()
    .prop('sAvatar', S.string().required())
    .prop('eTennisLevel', S.string().enum(eTennisLevel.value).required())
    .prop('bIsDiscoverable', S.boolean().required())
    .prop('bIsOpenToAllInvites', S.boolean().required())
    .prop('bIsOpenToCoaching', S.boolean().required())
    .prop('aWeeklyAvailability', S.array().items(
      S.object()
        .prop('sDay', S.string().enum(eWeekDays.value).required())
        .prop('bMorning', S.boolean().required())
        .prop('bAfternoon', S.boolean().required())
        .prop('bEvening', S.boolean().required())
    )),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }
}

const updateAvailabilitySchema = {
  tags,
  headers: authenticationHeaderSchema,
  body: S.object()
    .prop('bIsDiscoverable', S.boolean().required())
    .prop('bIsOpenToAllInvites', S.boolean().required())
    .prop('bIsOpenToCoaching', S.boolean().required())
    .prop('aWeeklyAvailability', S.array().items(
      S.object()
        .prop('sDay', S.string().enum(eWeekDays.value).required())
        .prop('bMorning', S.boolean().required())
        .prop('bAfternoon', S.boolean().required())
        .prop('bEvening', S.boolean().required())
    )),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }
}

const changePasswordSchema = {
  tags,
  body: S.object()
    .prop('sOldPassword', S.string().required().pattern(/^.{8,16}$/))
    .prop('sNewPassword', S.string().required().pattern(/^.{8,16}$/))
    .prop('sConfirmPassword', S.string().required().pattern(/^.{8,16}$/)),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }
}

const updateProfileSchema = {
  tags,
  headers: authenticationHeaderSchema,
  body: S.object()
    .prop('sFirstName', S.string())
    .prop('sLastName', S.string())
    .prop('sPhone', S.string())
    .prop('dDob', S.string())
    .prop('eGender', S.string().enum(eGender.value))
    .prop('sAvatar', S.string()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }
}

const getProfileSchema = {
  tags,
  headers: authenticationHeaderSchema,
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string())
      .prop('data', S.object()
        .prop('_id', S.string())
        .prop('sClubMatchId', S.string())
        .prop('sFirstName', S.string())
        .prop('isAdmin', S.boolean())
        .prop('bIsPushNotificationAllowed', S.boolean())
        .prop('sLastName', S.string())
        .prop('sPhone', S.string())
        .prop('dDob', S.string())
        .prop('sEmail', S.string())
        .prop('sAddress', S.string())
        .prop('sAddress2', S.string())
        .prop('sTown', S.string())
        .prop('sPostCode', S.string())
        .prop('eGender', S.string().enum(eGender.value))
        .prop('sAvatar', S.string())
        .prop('eTennisLevel', S.string())
        .prop('oAvailabilities', S.object()
          .prop('aWeeklyAvailability', S.array()
            .items(S.object()
              .prop('sDay', S.string().enum(Object.values(eWeekDays)))
              .prop('bMorning', S.boolean().default(false))
              .prop('bAfternoon', S.boolean().default(false))
              .prop('bEvening', S.boolean().default(false))
            )
          )
          .prop('bIsDiscoverable', S.boolean().default(false))
          .prop('bIsOpenToAllInvites', S.boolean().default(false))
          .prop('bIsOpenToCoaching', S.boolean().default(false)))
      ),

    default: errorResponseSchema
  }
}

const incidentReportSchema = {
  tags,
  headers: authenticationHeaderSchema,
  body: S.object()
    .prop('sText', S.string().maxLength(5000).required()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }
}

const updateClubInProfileSchema = {
  tags,
  headers: authenticationHeaderSchema,
  body: S.object()
    .prop('aClubs', S.array().items(S.string()).required()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string())
      .prop('sTitle', S.string()),
    400: S.object()
      .prop('sMessage', S.string())
      .prop('sTitle', S.string())
      .prop('data', S.object()
        .prop('aMemberOnlyClub', S.array().items(S.string()))
      )
  }
}

const listMembersClubSchema = {
  tags,
  headers: authenticationHeaderSchema,
  query: S.object()
    .prop('aRoleType', S.array().items(S.string().enum(eClubMemberType.value)))
    .prop('aSubRoleType', S.array().items(S.string().enum(eClubMemberSubType.value))),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string())
      .prop('data', S.object()
        .prop('aMembersClubs', S.array().items(
          S.object()
            .prop('eType', S.string().enum(eClubMemberType.value))
            .prop('_id', S.string())
            .prop('eClubMemberSubType', S.string().enum(eClubMemberSubType.value))
            .prop('sName', S.string())
        ))),
    default: errorResponseSchema
  }
}

const fetchMembersClubSchema = {
  tags,
  body: S.object()
    .prop('sClubMatchId', S.string().required())
    .prop('sEmail', S.string().format(S.FORMATS.EMAIL).required()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string())
      .prop('data', S.object()
        .prop('aMembersClubs', S.array().items(
          S.object()
            .prop('_id', S.string())
            .prop('sName', S.string())
        ))),
    '4xx': S.object()
      .prop('sMessage', S.string())
      .prop('sTitle', S.string()),
    default: errorResponseSchema
  }
}

const listClubsSchema = {
  tags,
  querystring: S.object()
    .prop('sSearch', S.string()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string())
      .prop('data', S.object()
        .prop('aClubs', S.array().items(
          S.object()
            .prop('_id', S.string())
            .prop('sName', S.string())
            .prop('sCounty', S.string())
            .prop('oClubBookingRules', S.object()
              .prop('bIsGuestAllowed', S.boolean())
            )
        ))),
    default: errorResponseSchema
  }
}

const levelInfoSchema = {
  tags,
  headers: authenticationHeaderSchema,
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string())
      .prop('data', S.object()
        .prop('oCurrentLevel', S.object()
          .prop('sLevel', S.string().enum(eTennisLevel.value))
          .prop('nPoint', S.number())
        )
        .prop('oNextLevel', S.object()
          .prop('sLevel', S.string().enum(eTennisLevel.value))
          .prop('nPointReq', S.number())
        )
        .prop('oPrevLevel', S.object()
          .prop('sLevel', S.string().enum(eTennisLevel.value))
          .prop('nPointReq', S.number())

        )
      ),
    default: errorResponseSchema
  }
}

const getUserPermissionsSchema = {
  tags,
  headers: authenticationHeaderSchema,
  query: S.object().prop('iClubId', S.string().required()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string())
      .prop('data', S.object()
        .prop('isAdministrator', S.boolean())
        .prop('aRoles', S.array().items(
          S.object()
            .prop('_id', S.string())
            .prop('sName', S.string())
            .prop('eRole', S.string().enum(eRole.value))
        ))
        .prop('aAllowedSections', S.array().items(S.string().enum(eAllowedSection.value)))
      ),
    default: errorResponseSchema
  }
}

const deleteAccountSchema = {
  tags,
  headers: authenticationHeaderSchema,
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string()),
    default: errorResponseSchema
  }

}

const updatePushNotificationSettingsSchema = {
  tags,
  headers: authenticationHeaderSchema,
  body: S.object()
    .prop('bIsPushNotificationAllowed', S.boolean().required()),
  response: {
    '2xx': S.object()
      .prop('sMessage', S.string())
      .prop('data', S.object()
        .prop('bIsPushNotificationAllowed', S.boolean())
      ),
    default: errorResponseSchema
  }
}

module.exports = {
  tags,
  userRegSchema,
  userLoginSchema,
  userForgotPassSchema,
  userLogoutSchema,
  userResetPasswordSchema,
  validateMemberSchema,
  sendOtpSchema,
  verifyOtpSchema,
  registerAvailabilitySchema,
  updateAvailabilitySchema,
  changePasswordSchema,
  updateProfileSchema,
  incidentReportSchema,
  updateClubInProfileSchema,
  listMembersClubSchema,
  fetchMembersClubSchema,
  listClubsSchema,
  getProfileSchema,
  levelInfoSchema,
  getUserPermissionsSchema,
  deleteAccountSchema,
  updatePushNotificationSettingsSchema
}
