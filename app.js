/*imports*/
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//Config JSON response
app.use(express.json()) // Aceitar JSON nas req e respostas

//Models
const User = require('./models/User')
const { restart } = require('nodemon')

//Open Route -Public Route
app.get('/',(req,res)=>{
    res.status(200).json({msg: "Bem vindo a nossa API!"})
})
//Private Route
app.get('/user/:id', checkToken , async (req,res)=>{

    const id = req.params.id

    // check if user exists
    const user = await User.findById(id,'-password')

    if(!user){
        return res.status(404).json({msg:'Usuario nao encotrado'})
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next){

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1] //para pegar o numero do token de autenticação
    
    if(!token){
        return res.status(401).json({msg: "Acesso Negado"})
    }

    try {

        const secret = process.env.SECRET
        jwt.verify(token, secret)

        next()
    } catch (error) {
        res.status(400).json({msg:" Token inválido"})
    }

}

// Register User            //async //why await response for database
app.post('/auth/register', async(req,res) =>{
    
    const {name, email, password, confirmpassword} = req.body
    // validations
    if(!name){
        return res.status(422).json({msg: 'O nome é obrigatório'})
    }
    if(!email){
        return res.status(422).json({msg: 'O email é obrigatório'})
    }
    if(!password){
        return res.status(422).json({msg: 'A senha é obrigatória'})

    }
    if(password !== confirmpassword){
        return res.status(422).json({msg: 'As senhas nao conferem! '})
    }

    // check if user exists
    // Query

    const userExist = await User.findOne({email: email})

    if(userExist){
        return res.status(422).json({msg: 'Por favor, utilize outro E-MAIL !'})
    }

    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash= await bcrypt.hash(password, salt)

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        
        await user.save()

        res.status(201).json({msg: 'Usuario criado com sucesso!'})
    } catch (error) {
        
        res.status(500).json({msg:'Acontenceu um erro no servidor! Tente novamente mais tarde'})

    }
})

// Login User
app.post('/auth/login', async(req,res)=>{

    const { email, password } = req.body

    if(!email){
        return res.status(422).json({msg: 'O email é obrigatório'})
    }
    if(!password){
        return res.status(422).json({msg: 'A senha é obrigatória'})

    }

    // check if user exists
    const user = await User.findOne({email: email})

    if(!user){
        return res.status(404).json({msg: 'Usuario nao encontrado ! '})
    }

    //check if password match
    const checkPassword = await bcrypt.compare( password, user.password)

    if(!checkPassword){
        return res.status(422).json({msg: 'Senha inválida! '})
    }

    try {
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id
        }, 
        secret,
       )

       res.status(200).json({msg:"Autenticação realizada com sucesso !", token})
    } catch (error) {

        res.status(500).json({msg:'Acontenceu um erro no servidor! Tente novamente mais tarde'})
    }



})

//Credencials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPassword}@cluster0.pvkebsw.mongodb.net/?retryWrites=true&w=majority`
    )
    .then(() => {
        console.log("Conectou ao banco")
        app.listen(3000)
    })
    .catch((err)=> console.log(err))


