const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require("../users/users-model")

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (!token) {
    return next({
      status: 401,
      message: "Token required"
    })
  }
  jwt.verify(token, JWT_SECRET, (err, decodedJWT) => {
    if (err) {
      return next({
        status: 401,
        message: "Token invalid"
      })
    }
    req.decodedJWT = decodedJWT
    next()
  })
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => {
  if (req.decodedJWT.role_name === role_name) {
    return next()
  } else {
    return next({
      status: 403,
      message: 'This is not for you'
    })
  }
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = async (req, res, next) => {
  const [existingUser] = await Users.findBy({ username: req.body.username })
  if (!existingUser) {
    return next({
      status: 401,
      message: "Invalid credentials"
    })
  } else {
    req.user = existingUser
    return next()
  }
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = async (req, res, next) => {
  const { role_name } = req.body

  // Account for empty role_name edge case
  if (!role_name || role_name.trim() === "") {
    req.role_name = "student"
    return next()
  } else {
    req.role_name = role_name.trim()
  }

  // Check if role name is valid
  if (req.role_name === "admin") {
    return next({
      status: 422,
      message: "Role name can not be admin"
    })
  }
  if (req.role_name.length > 32) {
    return next({
      status: 422,
      message: "Role name can not be longer than 32 chars"
    })
  }

  return next()
}

/*
  If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

  If role_name is missing from req.body, or if after trimming it is just an empty string,
  set req.role_name to be 'student' and allow the request to proceed.

  If role_name is 'admin' after trimming the string:
  status 422
  {
    "message": "Role name can not be admin"
  }

  If role_name is over 32 characters after trimming the string:
  status 422
  {
    "message": "Role name can not be longer than 32 chars"
  }
*/

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
