const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { BCRYPT_ROUNDS } = require("../secrets");
const Users = require("../users/users-model")
const bcrypt = require('bcryptjs')
const { tokenBuilder } = require("./auth-helpers")

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password } = req.body
    const hashedPassword = bcrypt.hashSync(password, BCRYPT_ROUNDS)
    const createdUser = await Users.add({
      username: username,
      password: hashedPassword,
      role_name: req.role_name
    })
    res.status(201).json({
      user_id: createdUser.user_id,
      username: createdUser.username,
      role_name: createdUser.role_name
    })
  } catch (err) {
    next(err)
  }
});
/**
  [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

  response:
  status 201
  {
    "user"_id: 3,
    "username": "anna",
    "role_name": "angel"
  }
 */


router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body
    const token = tokenBuilder(req.user)
    if (bcrypt.compareSync(password, req.user.password)) {
      res.status(200).json({
        message: `${username} is back`,
        token: token
      })
    } else {
      next({
        status: 401,
        message: "Invalid credentials"
      })
    }
  } catch (err) {
    next(err)
  }
});
/**
  [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "sue is back!",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
  }

  The token must expire in one day, and must provide the following information
  in its payload:

  {
    "subject"  : 1       // the user_id of the authenticated user
    "username" : "bob"   // the username of the authenticated user
    "role_name": "admin" // the role of the authenticated user
  }
 */

module.exports = router;
