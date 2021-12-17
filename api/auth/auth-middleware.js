const User = require('../users/users-model')

function checkValidBody(req, res, next) {
    console.log("MIDDLEWARE: check username and password are there")
    if (req.body.username === undefined || req.body.password === undefined){
        next({ status: 401, message: "username and password required"})
    }
    else{
        next()
    }

}

async function checkUsernameFree(req, res, next) {
    console.log("MIDDLEWARE: check username free")
    const username = req.body.username

    User.findBy({username})
        .then(([response]) => {
            if(!response){
                next()
            }
            else{
                next({status: 422, message: "username taken"})
            }
        })
        .catch(next)
  }
  
  function checkUsernameExists(req, res, next) {
    console.log("MIDDLEWARE: check username exists")

    const username = req.body.username

    User.findBy({username})
        .then(([response]) => {
            if(!response){
                next({status: 401, message: "invalid credentials"})
            }
            else{
                next()
            }
        })
        .catch(next)
  
  }
  
  
  module.exports = {
    checkUsernameFree,
    checkUsernameExists,
    checkValidBody
  }