const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const res = require("express/lib/response");

async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

async function validatePassword(plainPassword, hashedPassword) {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

//__Method for SignUp__//
exports.signup = async (request, response, next) => {
  try {
    const { email, password, role } = request.body;
    const hashedPassword = await hashPassword(password);
    const newUser = new User({
      email,
      password,
      hashedPassword,
      role: role || "basic",
    });
    const accessToken = jwt.sign(
      { userId: newUser._id },
      process.env.JWT_SECRET,
      {
        expiresIn: "Id",
      }
    );
    newUser.accessToken = accessToken;
    await newUser.save();
    response.json({
      data: newUser,
      accessToken,
    });
  } catch (error) {
    next(error);
  }
};

//__Method for User Login__//
exports.login = async (request, response, next) => {
  try {
    const { email, password } = request.body;
    const user = await User.findOne({ email });
    if (!user) return next(new Error("Email does not exist"));
    const validPassword = await validatePassword(password, user.password);
    if (!validPassword) return next(new Error("Password is not correct"));
    const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "Id",
    });
    await User.findByIdAndUpdate(user._id, { accessToken });
    response.status(200).json({
      data: { email: user.email, role: user.role },
      accessToken,
    });
  } catch (error) {
    next(error);
  }
};
