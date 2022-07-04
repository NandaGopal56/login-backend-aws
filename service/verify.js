const util = require('../utils/util')
const auth = require('../utils/auth')

function verify(requestBody) {
    if (!requestBody.user || !requestBody.user.username || !requestBody.token) {
        return util.buildResponse(401, {
            verifed: false,
            message: 'incorrect request body'
        })
    }

    const user = requestBody.user;
    const token = requestBody.token;
    const verification = auth.verifyToken(user.username, token)

    if (!verification.verifed) {
        return util.buildResponse(401, verification)
    }
    return util.buildResponse(200, {
        verifed: true,
        message: 'success',
        user: user,
        token: token
    })
}

module.exports.verify = verify;