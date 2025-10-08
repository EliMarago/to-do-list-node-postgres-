import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import passport from "passport";
import session from "express-session"; // gestisce le sessioni lato server
import bcrypt from "bcrypt";
import { Strategy } from "passport-local";
import { createRequire } from "module";
import env from "dotenv";

env.config();
console.log("DEBUG", process.env.PG_PORT, typeof process.env.PG_PORT);
const app = express();
const port = 4000;
const saltRounds = 10;

const require = createRequire(import.meta.url);
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});
app.get("/login", (req, res) => {
  res.render("login.ejs");
});
app.get("/register", (req, res) => {
  res.render("register.ejs");
});
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);
app.get("/reset-password", (req, res) => {
  res.render("reset-password.ejs");
});
app.get(
  "/auth/google/todolist",
  passport.authenticate("google", {
    successRedirect: "/todolist",
    failureRedirect: "/login",
  })
);
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
app.post("/reset-password", async (req, res) => {
  const email = req.body.email;
  const newPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rows.length === 0) {
      return res.send("❌ Nessun utente trovato con questa email");
    }
    const hashed = await bcrypt.hash(newPassword, saltRounds);
    await db.query("UPDATE users SET password = $1 WHERE email = $2", [
      hashed,
      email,
    ]);
    res.send(
      "Password aggiornata con successo ✅ <a href='/login'>Torna al login</a>"
    );
  } catch (error) {
    console.log(error);
    res.status(500).send("Errore interno del server");
  }
});
//visualizzare le task
app.get("/todolist", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    const result = await db.query(
      "SELECT * FROM tasks WHERE user_id = $1 ORDER BY id DESC",
      [req.user.id]
    );

    const tasks = result.rows;
    res.render("todolist.ejs", { tasks: result.rows, user: req.user });
  } catch (error) {
    console.log(error);
  }
});
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const result = await db.query("SELECT id FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rows.length > 0) {
      return res.send("Email already exists. Try logging in");
    }
    const hash = await bcrypt.hash(password, saltRounds);
    const inserted = await db.query(
      "INSERT INTO users(email,password)VALUES($1,$2)RETURNING *",
      [email, hash]
    );

    const user = inserted.rows[0];
    req.login(user, (err) => {
      if (err) {
        console.error("Login fallito", err);
        return res.redirect("/login");
      }
      return res.redirect("/todolist");
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/todolist",
    failureRedirect: "/login",
  })
);
passport.use(
  new Strategy({ usernameField: "username" }, async (email, password, cb) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        email,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const checkPassword = user.password;

        bcrypt.compare(password, checkPassword, (err, result) => {
          if (err) {
            console.log("Error comparing password", err);
          } else {
            if (result) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (error) {
      console.log(error);
      return cb(error);
    }
  })
);
//aggiungere una task
app.post("/todolist", async (req, res) => {
  const tasks = req.body.task;
  const userId = req.user.id;
  try {
    await db.query(
      "INSERT INTO tasks(user_id,task,completed)VALUES($1,$2,false)",
      [userId, tasks]
    );
    res.redirect("/todolist");
  } catch (error) {
    console.log(error);
  }
});
//completare una task
app.post("/todolist/complete/:id", async (req, res) => {
  await db.query("UPDATE tasks SET completed = true WHERE id = $1", [
    req.params.id,
  ]);
  res.redirect("/todolist");
});
//eliminare una task
app.post("/todolist/delete/:id", async (req, res) => {
  await db.query("DELETE FROM tasks WHERE id = $1", [req.params.id]);
  res.redirect("/todolist");
});
passport.serializeUser((user, cb) => {
  cb(null, user.id);
});
passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT id,email FROM users  WHERE id = $1", [
      id,
    ]);
    cb(null, result.rows[0] || null);
  } catch (error) {
    cb(null);
  }
});
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:4000/auth/google/todolist",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      try {
        const email = profile.emails?.[0].value;
        if (!email) {
          console.error("nessuna email trovata", profile);
          return cb(new Error("Email non disponibile da google"));
        }
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email,password) VALUES($1,$2)",
            [email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          cb(null, result.rows[0]);
        }
      } catch (error) {
        cb(error);
      }
    }
  )
);
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
