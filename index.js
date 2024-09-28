import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcryptjs";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth20";
import session from "express-session";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;

// Setup session management
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
    })
);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

// PostgreSQL Client
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();

async function findOrCreateUser(profile) {
    const { id, displayName, emails } = profile;
    const email = emails[0].value;

    let result = await db.query("SELECT * FROM users WHERE google_id = $1", [id]);
    let user = result.rows[0];

    if (user) {
        return user;
    } else {
        // Generate a random password or set a default password
        const password = await bcrypt.hash("default_password", saltRounds);
        result = await db.query(
            "INSERT INTO users (google_id, username, email, password) VALUES ($1, $2, $3, $4) RETURNING *",
            [id, displayName, email, password]
        );
        user = result.rows[0];
        console.log(user);
        return user;
    }
}


function ensureAuthenticated(req, res, next){
    if (req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
}

passport.use("local", new LocalStrategy(
    async (username, password, done) => {
        try {
            const result = await db.query(
                "SELECT * FROM users_without WHERE username = $1", [username]
            );
            if (result.rows.length === 0) {
                return done(null, false, {message : "Incorrect username"});
            }
            const user = result.rows[0];
            console.log("User password:", user.password);  // Debugging line
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return done(null, false, {message : "Incorrect password"});
            }
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));



passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
        const user = result.rows[0];
        if (!user) {
            return done(null, false);
        }
        const isGoogleUser = await checkIfGoogleUser(user.username);
        if (isGoogleUser) {
            deserializeGoogleUser(user.username, done);
        } else {
            deserializeNormalUser(user.username, done);
        }
    } catch (error) {
        done(error);
    }
});

async function deserializeGoogleUser(username, done) {
    // If using a separate table for Google users, use this function
    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        done(null, user);
    } catch (error) {
        done(error);
    }
}

async function deserializeNormalUser(username, done) {
    // If using a separate table for normal users, use this function
    try {
        const result = await db.query('SELECT * FROM users_without WHERE username = $1', [username]);
        const user = result.rows[0];
        done(null, user);
    } catch (error) {
        done(error);
    }
}

async function checkIfGoogleUser(username) {
    // Implement this function to check if the user is a Google user
    // For example, you can check if the user has a Google ID associated with their account
    const result = await db.query('SELECT google_id FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) {
        return false; // User not found, assume not a Google user
    }
    return user.google_id !== null;
}





passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'  // Using environment variable
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const user = await findOrCreateUser(profile);
        return done(null, user);
    } catch (error) {
        return done(error);
    }
}));




app.get("/", ensureAuthenticated, (req, res) => {
    console.log(req.user);
    res.render("login.ejs", {user : req.user});
});

app.get("/about", ensureAuthenticated, (req, res) => {
    res.render("about.ejs", { user: req.user });
});

app.get("/skills", ensureAuthenticated, (req, res) => {
    res.render("skills.ejs", { user: req.user });
});

app.get("/projects", ensureAuthenticated, (req, res) => {
    res.render("projects.ejs", { user: req.user });
});


app.get('/certificates', ensureAuthenticated ,(req, res) => {
    res.render('certificates.ejs', {user : req.user});
});


app.get("/home", ensureAuthenticated ,(req, res) => {
    res.render("home.ejs", {user : req.user});
})

app.get("/login", (req, res) => {
    res.render("login.ejs", {user : req.user});
});

app.get("/register", (req, res) => {
    res.render("register.ejs", {user : req.user});
})

app.post(
    "/login",
    passport.authenticate("local", {
      successRedirect: "/home",
      failureRedirect: "/login",
    })
);

app.post("/register", async (req, res) => {
    const {username, email, password} = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        await db.query('INSERT INTO users_without (username, password, email) VALUES ($1, $2, $3)', [username, hashedPassword, email]);
        res.redirect('/login');
    } catch (err) {
        console.log(err);
        res.redirect('/register');
    }
});


app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { 
    successRedirect: '/home',
    failureRedirect: '/login'
}));

// Logout route
app.post('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.redirect('/');
    });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

