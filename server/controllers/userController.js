const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

async function validatePassword(plainPassword, hashedPassword) {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

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
