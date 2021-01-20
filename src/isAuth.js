
const { verify } = require('jsonwebtoken');

const isAuth = req => {
    const auth = req.headers['authorization'];
    if (!auth) throw new Error("You need to login");
    // Bareer fssdgjsgkjgkg
    const token = auth.split(' ')[1];

    const { userId } = verify(token, process.env.ACCESS_TOKEN);
    return userId;
}

module.exports = {
    isAuth
}