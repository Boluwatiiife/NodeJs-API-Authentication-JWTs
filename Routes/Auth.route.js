const express = require('express')
const router = express.Router();
const createError = require('http-errors')
const User = require('../Models/User.model')
const { authSchema } = require('../helpers/validation_schema')
const { signAcessToken, signRefreshToken, verifyRefreshToken } = require('../helpers/jwt_helper')


router.post('/register', async(req,res,next) => {
    try{
        // const {email, password} = req.body
        // if(!email || !password) throw createError.BadRequest()
        const result = await authSchema.validateAsync(req.body)

            const doesExist = await User.findOne({ email: result.email})
            if(doesExist)
                 throw createError.Conflict(`${result.email} has already been registered`)
            
            const user = new User(result)
            const savedUser = await user.save()
            const acessToken = await signAcessToken(savedUser.id)
            const refreshToken = await signRefreshToken(savedUser.id)

            res.send({ acessToken, refreshToken })

    }catch(error){
        if(error.isJoi === true)error.status = 422
        next(error)
    }
})

router.post('/login', async(req,res,next) => {
    try{
        const result = await authSchema.validateAsync(req.body)
        const user = await User.findOne({ email: result.email })

        if(!user) throw createError.NotFound("User not registered")

        const isMatch = await user.isValidPassword(result.password)
        if(!isMatch) throw createError.Unauthorized('Username/Password not valid')


        const accessToken = await signAcessToken(user.id)
        const refreshToken = await signRefreshToken(user.id)


        res.send({ accessToken, refreshToken })

        
    }catch(error){
        if(error.isJoi === true) return next(createError.BadRequest("Invalid Username/Password"))
        next(error)
    }
})

router.post('/refresh-token', async(req,res,next) => {
    // console.log("Refresh Token Secret:", process.env.REFRESH_TOKEN_SECRET);

    try {
        const{ refreshToken } = req.body
        console.log('refresh token', refreshToken)
        if(!refreshToken) throw createError.BadRequest('refresh token is required')
        const userId = await verifyRefreshToken(refreshToken)

        const accessToken = await signAcessToken(userId)
        const refToken = await signRefreshToken(userId)
        res.send({ accessToken: accessToken, refreshToken: refToken }) 

    } catch (error) {
        next(error)
    }
})


router.post('/test-body', (req, res) => {
    console.log("Request body:", req.body); 
    res.send("Check console for output");
});



router.delete('/logout', async(req,res,next) => {
    res.send("logout route")
})






module.exports =router