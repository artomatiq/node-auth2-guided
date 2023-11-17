const jwt = require('jsonwebtoken')
const {JWT_SECRET} = require('../../config/index')

// AUTHENTICATION
const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (token) {
    jwt.verify(token, JWT_SECRET, (error, decoded) => {
      if (error) {
        next({status: 401, message: `token bad:${error.message} `})
      }
      else {
        req.decodedJwt = decoded
        next()
      }
    })
  }
  else {
    next({status:401, message: 'what? no token?'})
  }
}

// AUTHORIZATION
const checkRole = (req, res, next) => {
  next()
}

module.exports = {
  restricted,
  checkRole,
}
