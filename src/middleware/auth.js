const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("../users/model");

const saltRounds = parseInt(process.env.SALT_ROUNDS);

const hashPass = async (req, res, next) => {
  try {
    console.log("req.body.password before hash:", req.body.password);

    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
    req.body.password = hashedPassword;

    console.log("req.body.password after hash:", req.body.password);

    next();
  } catch (err) {
    res.status(501).json({ message: err.message, err: err });
  }
};

const comparePass = async (req, res, next) => {
  try {
    const user = await User.findOne({ where: { username: req.body.username } });
    if (!user) {
      res.status(401).json({ message: "invalid username" });
      return;
    }

    const matched = await bcrypt.compare(
      req.body.password,
      user.dataValues.password
    );

    console.log(matched);

    if (!matched) {
      res.status(401).json({ message: "no!!!!!!!!!!!" });
      return;
    }
    //...

    // https://www.npmjs.com/package/bcrypt

    //compare passwords
    // what we will need;

    // plain text password (e.g. 'mypassword123) & the hashed password on the DB

    // how do we get plain text password? send it in the request body

    // how do we get the hashed password? find the user

    // How do we find the user? by the username - sent in the request body

    // we've found the user - then, use bcrypt to compare.

    // const matched = use bcrypt.compare(plaintext, hashed password)

    //or

    // req.matched = use bcrypt.compare(plaintext, hashed password) (harder way)

    // if matched false - response with code from unauthorised

    // next()
    req.user = user;
    next();
  } catch (err) {
    res.status(501).json({ message: err.message, err: err });
  }
};

const tokenCheck = async (req, res, next) => {
  try {
    console.log(req.header("Authorization"));

    // 1 check request headers

    if (!req.header("Authorization")) {
      throw new Error("no token passed");
    }

    // 2 get the jwt from Headers

    const token = req.header("Authorization").replace("Bearer ", "");

    // 3 decode the token using SECRET

    const decodedToken = await jwt.verify(token, process.env.SECRET);

    // 4 get user with Id

    const user = await User.findOne({ where: { id: decodedToken.id } });

    // 5 if !user send 401 response

    if (!user) {
      res.status(401).json({ message: "Not Authorized" });
      return;
    }

    // 6 pass on user data

    req.authCheck = user;

    next();
  } catch (err) {
    res.status(501).json({ message: err.message, err: err });
  }
};

const emailValidation = async (req, res, next) => {
  // validate email
  next();
};

const passwordValdation = async (req, res, next) => {
  // validate password
  next();
};

module.exports = {
  hashPass: hashPass,
  comparePass: comparePass,
  tokenCheck: tokenCheck,
};
