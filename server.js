require(`dotenv`).config()
const express = require("express");
const jwt = require(`jsonwebtoken`)
const bcrypt = require("bcrypt");
const cookieParser = require(`cookie-parser`)
const app = express();
const { Pool } = require('pg');
const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});
//creates the table
(async () => {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users(
        id SERIAL PRIMARY KEY,
        username VARCHAR(20) NOT NULL UNIQUE,
        password VARCHAR(100) NOT NULL
        );
        `);
})();
app.set("view engine","ejs");
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"));
app.use(cookieParser())
//
app.use(function (req,res,next){
    res.locals.errors = []
    //try to decode cookie that is incoming
    try{
        const decode = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
        req.user = decode
    }
    catch(err){
        console.log(err)
        req.user = false
    }
    res.locals.user = req.user
    next()
})



//Creates a router to homepage
app.get("/",(req, res) => {
    if(req.user){
        return res.render('dashboard')
    }

    res.render("homepage")
})
//Creates a router to login page
app.get("/login", (req, res) => {
    res.render("login")
})
app.get("/logout", (req,res) => {
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

app.post("/login", (req, res) => {
    const errors = []
    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    if(req.body.username.trim() === "" || req.body.password === "") errors.push("Do not pass an empty password/username");
    
    if (errors.length) {
        return res.render("login", {errors})
    }

    res.send("Thank You!!!")
})
app.post("/register",async(req,res) =>{
    const errors = []
    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()
    if(!req.body.username) {errors.push("You must provide a username")}
    if (req.body.username && req.body.username.length < 3 || req.body.username && req.body.username.length > 10){
        errors.push("Username must be atleast 3 characters but not more than 10.")
    }
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)){
        errors.push("Username could contain letters and number")
    }

    if(!req.body.password) {errors.push("You must provide a password")}
    if (req.body.password && req.body.password.length < 6 || req.body.password && req.body.password.length > 15){
        errors.push("Password must be atleast 6 characters but not more than 15.")
    }

    if (errors.length){
        return res.render("homepage", {errors})
    }
    
    // save the user into a database
    let newlyAddedID;
    try{
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(req.body.password, salt)
        const result = await pool.query(`
            INSERT INTO users (username,password) VALUES ($1, $2) RETURNING id, username`,[req.body.username, hash]);
        newlyAddedID = result.rows[0]
    }
    catch(e){
        if (e.code === '23505') errors.push('Username taken');
        else errors.push('DB error');
        return res.render('homepage', { errors });
    }
    // log user by giving them a cookie
    const tokenVal = jwt.sign({exp: Math.floor(Date.now() / 1000)+60 *60*24, id: newlyAddedID.id, username: newlyAddedID.username}, process.env.JWTSECRET)

    res.cookie("ourSimpleApp",tokenVal, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    res.redirect("/")
})
app.listen(3000)