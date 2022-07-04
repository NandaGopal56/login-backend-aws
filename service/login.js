const AWS = require('aws-sdk')
AWS.config.update({
    region: 'ap-south-1'
})

const util = require('../utils/util')
const auth = require('../utils/auth')
const bcrypt = require('bcryptjs');

const dynamodb = new AWS.DynamoDB.DocumentClient();
const userTable = 'login-users'

async function login(user) {
    const username = user.username
    const password = user.password

    if (!user || !password) {
        return util.buildResponse(401, {
            message: 'username and password are required'
        })
    }

    const dynamoUser = await getUser(username);
    if (!dynamoUser || !dynamoUser.username) {
        return util.buildResponse(403, { message: 'User does not exist' })
    }

    if (!bcrypt.compareSync(password, dynamoUser.password)) {
        return util.buildResponse(403, { message: 'Password is incorrect' })
    }

    const userInfo = {
        username: dynamoUser.username,
        password: dynamoUser.password
    }

    const token = auth.generateToken(userInfo)
    const response = {
        user: userInfo,
        token: token
    }

    return util.buildResponse(200, response);
}

async function getUser(username) {
    const params = {
        TableName: userTable,
        Key: {
            username: username
        }
    }

    return await dynamodb.get(params).promise().then(response => {
        return response.Item;
    }, error => {
        console.error('There is an error: ', error);
    })
}

module.exports.login = login;