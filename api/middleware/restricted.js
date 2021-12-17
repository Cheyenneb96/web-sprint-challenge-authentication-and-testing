const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets");

module.exports = (req, res, next) => {
  const token = req.headers.authorization;

  //if no token, don't allow access
  if (!token){
    return next({status: 401, message: "token required"})
  }

  //if token then verify it's valid
  jwt.verify(token, JWT_SECRET, (err, decoded) =>{
    if(err){
      return next({status:401, message: "token invalid"})
    }
    req.goodJWT = decoded
    next()
  })
  /*
    IMPLEMENT
    1- On valid token in the Authorization header, call next.
    2- On missing token in the Authorization header,
      the response body should include a string exactly as follows: "token required".
    3- On invalid or expired token in the Authorization header,
      the response body should include a string exactly as follows: "token invalid".
  */
};