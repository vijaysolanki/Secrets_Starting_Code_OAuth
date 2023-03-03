//jshint esversion:10
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(
  bodyParser.urlencoded({
    extended: true
  })
);

// configure express session
app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false
  })
);

// initialize passport and configure  to use session
app.use(passport.initialize());
app.use(passport.session());

//connect to db
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set("useCreateIndex", true);

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", function() {
  console.log("Successfully connected to DB");
});

// create schema for collection
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// configure passportLocalMongoose as plugin to db schema
userSchema.plugin(passportLocalMongoose);
// this is to use findOrCreate method
userSchema.plugin(findOrCreate);

//create collection and collecte to it.
const User = mongoose.model("User", userSchema);

//configure passport strategy
passport.use(User.createStrategy());
//this is best way to work with passport serialization of users
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//google strategy for OAuth with google account
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, cb) {
      // console.log("accessToken = " + accessToken);
      // console.log("refreshToken = " + refreshToken);
      console.log(profile);
      for (var variable in profile) {
        if (profile.hasOwnProperty(variable)) {
          console.log(variable);
        }
      }

      User.findOrCreate({googleId: profile.id}, function(err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  // if (req.isAuthenticated()) {
  //   console.log("User authenticate Successfully");
  //   res.render("secrets", {title: "register"});
  // } else {
  //   console.log("User not authorized");
  //   res.redirect("/login");
  // }
  User.find({secret: {$ne: null}}, (err, foundUsers) => {
    if (err) {
      console.log(err);
    } else {
      res.render("secrets", {title: "register", users: foundUsers});
    }
  });
});

app.get("/secrets/:title", (req, res) => {
  if (req.isAuthenticated()) {
    console.log("User authenticate Successfully");
    res.render("secrets", {title: req.params.title, users: []});
  } else {
    console.log("User not authorized");
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/login");
});

app.get("/auth/google", passport.authenticate("google", {scope: ["profile"]}));

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {failureRedirect: "/login"}),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  }
);

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/register", (req, res) => {
  User.register(
    {username: req.body.username},
    req.body.password,
    (err, newUser) => {
      if (err) {
        // res.send(err);
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function() {
          res.redirect("/secrets");
        });
      }
    }
  );
});

/*app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/"
  })
);*/

app.post("/login", (req, res) => {
  const username = req.body.username;
  const pwd = req.body.password;

  const user = new User({
    username: username,
    password: pwd
  });

  req.login(user, err => {
    if (err) {
      console.log(err);
      res.redirect("/login");
    } else {
      passport.authenticate("local")(req, res, (err, user) => {
        console.log(" authenicating user");
        res.redirect("/secrets/login");
      });
    }
  });
});

app.post("/submit", (req, res) => {
  // console.log("user details: " + req.user);
  User.findById(req.user.id, (err, user) => {
    if (err) {
      console.log(err);
    } else {
      if (user) {
        user.secret = req.body.secret;
        user.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.listen(process.env.PORT || 3000, (req, res) => {
  console.log("Server started at port 3000");
});
