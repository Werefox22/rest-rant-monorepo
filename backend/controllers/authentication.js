const router = require('express').Router()
const db = require("../models")
const bcrypt = require('bcrypt')
const jwt = require('json-web-token')

const { User } = db

// login
router.post('/', async (req, res) => {
    
    let user = await User.findOne({
        where: { email: req.body.email }
    })

    console.log(user)

    if (!user || !await bcrypt.compare(req.body.password, user.password_digest)) {
        res.status(404).json({
            message: `Could not find a user with the provided username and password`
        })
    } else {
        // successful login
        const result = await jwt.encode(process.env.JWT_SECRET, { id: user.userId })
        res.json({ user: user, token: result.value })
    }
})

// get current user
router.get('/profile', async (req, res) => {
    try {
        const [ authenticationMethod, token ] = req.headers.authorization.split(' ')

        if (authenticationMethod == 'Bearer') {
            const result = await jwt.decode(process.env.JWT_SECRET, token)

            const { id } = result.value

            let user = await User.findOne({
                where: {
                    userId: id
                }
            })
            res.json(user)
        }
    } catch {
        res.json(null)
    }
})

module.exports = router
