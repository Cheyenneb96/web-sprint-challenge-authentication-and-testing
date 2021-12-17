const router = require('express').Router();
const bcrypt = require('bcryptjs')

const User = require('../users/users-model')

const BCRYPT_ROUNDS = 3

const {
  checkUsernameFree,
  checkUsernameExists,
  checkValidBody
} = require('./auth-middleware')

const { tokenBuilder } = require('./auth-helpers')

router.post('/register', checkValidBody, checkUsernameFree, (req, res, next) => {
  console.log("AUTH-ROUTER: [POST] /REGISTER")
  let newUser = req.body
  newUser.password = bcrypt.hashSync(newUser.password, BCRYPT_ROUNDS)

  User.add(newUser)
    .then(response => {
      res.status(201).json(response)
    })
    .catch(next)

  
});

router.post('/login', checkValidBody, checkUsernameExists, (req, res, next) => {
  console.log("AUTH-ROUTER: [POST] /LOGIN")
  let { username, password } = req.body;

  User.findBy({username})
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)){
        const token = tokenBuilder(user)
        res.status(200).json({
          message:`welcome, ${user.username}`,
          token: token
        })
      }
      else{
        next({status: 401, message: "invalid credentials"})
      }
    })
    .catch(next)

  
});


module.exports = router;

