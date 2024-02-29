const { Router } = require("express");

const userRouter = Router();

const { hashPass, comparePass, tokenCheck } = require("../middleware/auth");

const {
  signupUser,
  getAllUsers,
  login,
  getOneUser,
  updateUser,
} = require("./controllers");

userRouter.post("/users/signup", hashPass, signupUser);
userRouter.get("/users/getusers", getAllUsers);
userRouter.get("/users/getOneUser/:username", getOneUser);
userRouter.put("/users/updateUser", updateUser);

userRouter.post("/users/login", comparePass, login);
userRouter.get("/users/authCheck", tokenCheck, login);

module.exports = userRouter;
