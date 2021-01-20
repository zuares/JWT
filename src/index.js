require('dotenv/config');

const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { fakeDB } = require('./fakeDB')
const { hash, compare } = require('bcrypt')
const { isAuth } = require('./isAuth')
const {
    createAccessToken, createRefreshToken,
    sendRefreshToken, sendAccessToken
} = require('./token');
const { verify } = require('jsonwebtoken');


// Konfigurasi
const app = express();

app.use(cookieParser());
app.use(express.json());

app.use
    (
        cors
            (
                {
                    origin: 'http://localhost:3000',
                    credentials: true
                }
            )
    );
app.use(express.urlencoded({ extended: true }));

// End of Konfigurasi

// Menjalankan server di port tertentu
app.listen
    (
        process.env.PORT,
        () => console.log(`Server listening on port ${process.env.PORT}`)
    )


// Register 

app.post('/register', async (req, res) => {
    try {
        // Tangkap email dan password
        const { email, password } = req.body;
        // Cek user 
        const user = fakeDB.find(user => user.email === email);
        if (user) throw Error(`Email has already exists`)
        // Hash password
        const passwordHash = await hash(password, 12);
        // Masukan ke Database
        fakeDB.push({ id: fakeDB.length, email, password: passwordHash })
        // Kirim resposne
        res.send({ msg: `User successfully created` })
        console.log(fakeDB);
    } catch (err) {
        // Response jika error
        res.send({ error: `${err.message}` })
    }
})

// Login

app.post('/login', async (req, res) => {
    try {
        // Tangkap email dan password
        const { email, password } = req.body;

        // Cek user 
        const user = fakeDB.find(user => user.email === email);
        if (!user) throw Error(`Email doesnt exists`)

        const valid = await compare(password, user.password);
        if (!valid) throw Error(`Incorect password`)

        // Buat access dan refreshToken
        const accessToken = createAccessToken(user.id);
        const refreshToken = createRefreshToken(user.id);
        // Simpan refresh token di database
        user.refreshToken = refreshToken;
        // Kirim resposne
        sendRefreshToken(res, refreshToken);
        sendAccessToken(req, res, accessToken);

    } catch (err) {
        // Response jika error
        res.send({ error: `${err.message}` })
    }
})

// Logout

app.post('/logout', async (req, res) => {
    try {
        res.clearCookie('refreshToken', {
            domain: "localhost", path: " /refresh_token"
        });
        res.send({
            message: 'Logged out'
        })

    } catch (err) {
        // Response jika error
        res.send({ error: `${err.message}` })
    }
})

// protected

app.get('/protected', async (req, res) => {
    try {
        const userId = isAuth(req);
        if (userId !== null)
            res.send({ message: 'This is protected data' })

    } catch (err) {
        // Response jika error
        res.send({ error: `${err.message}` })
    }
})

app.post('/refresh_token', async (req, res) => {
    try {
        const token = req.cookies.refreshToken;

        if (!token)
            res.send({ accessToken: '' })
        let payload;
        try {
            payload = verify(token, process.env.REFRESH_TOKEN);
        } catch (err) {
            res.send({ accessToken: '' });
        }
        let user = fakeDB.find(user => user.id == payload.id);
        if (!user)
            return res.send({ accessToken: '' });
        if (user.refreshToken !== token)
            return res.send({ accessToken: '' });
        const accessToken = createAccessToken(user.id)
        const refreshToken = createRefreshToken(user.id)
        user.refreshToken = refreshToken

        sendRefreshToken(res, refreshToken)
        return res.send({ accessToken })

    } catch (err) {
        // Response jika error
        res.send({ error: `${err.message}` })
    }
})