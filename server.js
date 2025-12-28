const express = require("express");
const app = express();
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

app.post("/register",(req,res) =>{
    const errors = []
    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()
    if(!req.body.username) {errors.push("You must provide a username")}
    if (req.body.username && req.body.username.length < 3 || req.body.username && req.body.username.length > 0){
        errors.push("Username must be atleast 3 characters but not more than 10.")
    }
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)){
        error.push("Username could contain letters and number")
    }

    if (errors.length){
        return res.render("homepage", {errors})
    }
    else{
        res.send("Thank you")
    }
    
})
app.listen(3000)