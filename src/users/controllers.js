const sequelize = require("../db/connection");
const User = require("./model");
const jwt = require("jsonwebtoken");

const signupUser = async (req, res) => {
  try {
    const user = await User.create({
      username: req.body.username,
      email: req.body.email,
      password: req.body.password,
    });
    res.status(201).json({ message: `${user.username} added`, user: user });
  } catch (err) {
    res.status(500).json({ message: err.message, err: err });
  }
};

const getAllUsers = async (req, res) => {
  try {
    const users = await User.findAll();
    res.status(200).json({ message: "all users", users: users });
  } catch (err) {
    res.status(500).json({ message: err.message, err: err });
  }
};

const getOneUser = async (req, res) => {
  try {
    const user = await User.findOne({
      where: { username: req.params.username },
      username: req.body.username,
      email: req.body.email,
      password: req.body.password,
    });

    console.log("Route: ", req.path, user.username, user.email, user.password);
    if (!user) {
      res.status(404).json({ message: "username not found" });
    }

    res.status(200).json({
      message: "user found",
      username: user.username,
      email: user.email,
      password: user.password,
    });

    // res.status(200).json({ message: "user found", user.username, user.email, user.password });
  } catch (err) {
    res.status(500).json({ message: err.message, err: err });
  }
};

const login = async (req, res) => {
  try {
    if (req.authCheck) {
      const user = {
        id: req.authCheck.id,
        username: req.authCheck.username,
      };

      res
        .status(201)
        .json({ message: "persistent login successful", user: user });
      return;
    }

    const token = await jwt.sign({ id: req.user.id }, process.env.SECRET);

    console.log(token);

    const user = {
      id: req.user.id,
      username: req.user.username,
      token: token,
    };
    console.log(user);

    res.status(201).json({ message: "hello from the BE", user: user });
  } catch (err) {
    res.status(500).json({ message: err.message, err: err });
  }
};

const updateUser = async (req, res) => {
  try {
    const userToUpdate = await User.findOne({
      where: { username: req.user.username },
    });
    const updatedUserDetails = {
      username: req.body.username,
      email: req.body.email,
    };
    userToUpdate.update(updatedUserDetails);
    res.send({ message: "user updated", userToUpdate });
  } catch (error) {
    res.send({ message: "its gone pete tong", error: error });
  }
};

module.exports = {
  signupUser: signupUser,
  getAllUsers: getAllUsers,
  login: login,
  getOneUser: getOneUser,
  updateUser: updateUser,
};
