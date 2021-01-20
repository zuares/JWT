const { sign } = require('jsonwebtoken')

const createAccessToken = (id) => {
    return sign({ id }, process.env.ACCESS_TOKEN, { expiresIn: '15m' })
}

const createRefreshToken = (id) => {
    return sign({ id }, process.env.REFRESH_TOKEN, { expiresIn: '7d' })
}

const sendAccessToken = (req, res, token) => {
    res.send({
        token,
        email: req.body.email
    })
}

const sendRefreshToken = (res, token) => {
    res.cookie('refreshToken', token, {
        httpOnly: true,
        path: '/refresh_token'
    })
}

module.exports = {
    createAccessToken,
    createRefreshToken,
    sendAccessToken, sendRefreshToken
}