const router = require("express").Router();
const Users = require('../users/users-model');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, (req, res, next) => {
    let user = req.body;

    const rounds = process.env.BCRYPT_ROUNDS || 8;
    const hash = bcrypt.hashSync(user.password, rounds);

    user.password = hash;
    user.role_name = req.role_name;

    Users.add(user)
      .then(saved => {
        res.status(201).json(saved)
      })
      .catch(next)


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
});


router.post("/login", checkUsernameExists, (req, res, next) => {

  let { username , password } = req.body;

  Users.findBy({username})
  .then( ([user]) => {
    if(user && bcrypt.compareSync(password, user.password)){
      const token = generateToken(user);
      res.status(200).json({
        message: `${user.username} is back`,
        token,
      });
    } else {
      res.status(401).json({ message: 'invalid credentials' });
    }
  })
  .catch(next)

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
});

function generateToken (user) {
  const payload = {
    subject: user.user_id, // sub in payload is what the token is about
    username: user.username,
    role_name: user.role_name
  };

  const options = {
    expiresIn: '1d', // show other available options in the library's documentation
  };

  const token = jwt.sign(
    payload,
    JWT_SECRET,
    options
  )
  
  return token
}

module.exports = router;
