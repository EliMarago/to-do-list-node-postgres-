import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import passport from "passport";
import session from "express-session"; // gestisce le sessioni lato server
import bcrypt from "bcrypt";
import { Strategy } from "passport-local";
import env from "dotenv";

env.config();
console.log("DEBUG", process.env.PG_PORT, typeof process.env.PG_PORT);
const app = express();
const port = 4000;
const saltRounds = 10;

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

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
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
    res.render("todolist.ejs", { tasks: result.rows });
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
    } else {
      const hash = await bcrypt.hash(password, saltRounds);
      const inserted = await db.query(
        "INSERT INTO users(email,password)VALUES($1,$2)RETURNING *",
        [email, hash]
      );
    }
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

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
