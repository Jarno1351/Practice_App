require(`dotenv`).config()
const express = require("express");
const jwt = require(`jsonwebtoken`)
const bcrypt = require("bcrypt");
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
//
app.use(function (req,res,next){
    res.locals.errors = []
    next()
})

app.set("view engine","ejs");
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"));
//Creates a router to homepage
app.get("/",(req, res) => {
    res.render("homepage")
})
//Creates a router to login page
app.get("/login", (req, res) => {
    res.render("login")
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
    try{
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(req.body.password, salt)
        await pool.query(`
            INSERT INTO users (username,password) VALUES ($1, $2)`,[req.body.username, hash]);    
    }
    catch(e){
        if (e.code === '23505') errors.push('Username taken');
        else errors.push('DB error');
        return res.render('homepage', { errors });
    }
    // log user by giving them a cookie
    const tokenVal = jwt.sign(app, b)

    res.cookie("ourSimpleApp","supersecret", {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    res.send("Thankyou")
})
app.listen(3000)