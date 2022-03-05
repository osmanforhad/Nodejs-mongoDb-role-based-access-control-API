const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const { roles } = require("../roles");

async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

async function validatePassword(plainPassword, hashedPassword) {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

exports.grantAccess = function (action, resource) {
  return async (request, response, next) => {
    try {
      const permission = roles.can(request.user.role)[action](resource);
      if (!permission.granted) {
        return response.status(401).json({
          error: "You don't have enough permission to perform this action",
        });
      }
      next();
    } catch (error) {
      next(error);
    }
  };
};

exports.allowIfLoggedin = async (request, response, next) => {
  try {
    const user = response.locals.loggedInUser;
    if (!user)
      return response.status(401).json({
        error: "You need to be logged in to access this route",
      });
    request.user = user;
    next();
  } catch (error) {
    next(error);
  }
};

exports.signup = async (request, response, next) => {
  try {
    const { role, email, password } = request.body;
    const hashedPassword = await hashPassword(password);
    const newUser = new User({
      email,
      password: hashedPassword,
      role: role || "basic",
    });
    const accessToken = jwt.sign(
      { userId: newUser._id },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );
    newUser.accessToken = accessToken;
    await newUser.save();
    response.json({
      data: newUser,
      message: "You have signed up successfully",
    });
  } catch (error) {
    next(error);
  }
};

exports.login = async (request, response, next) => {
  try {
    const { email, password } = request.body;
    const user = await User.findOne({ email });
    if (!user) return next(new Error("Email does not exist"));
    const validPassword = await validatePassword(password, user.password);
    if (!validPassword) return next(new Error("Password is not correct"));
    const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
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

exports.getUsers = async (request, response, next) => {
  const users = await User.find({});
  response.status(200).json({
    data: users,
  });
};

exports.getUser = async (request, response, next) => {
  try {
    const userId = request.params.userId;
    const user = await User.findById(userId);
    if (!user) return next(new Error("User does not exist"));
    response.status(200).json({
      data: user,
    });
  } catch (error) {
    next(error);
  }
};

exports.updateUser = async (request, response, next) => {
  try {
    const { role } = request.body;
    const userId = request.params.userId;
    await User.findByIdAndUpdate(userId, { role });
    const user = await User.findById(userId);
    response.status(200).json({
      data: user,
    });
  } catch (error) {
    next(error);
  }
};

exports.deleteUser = async (request, response, next) => {
  try {
    const userId = request.params.userId;
    await User.findByIdAndDelete(userId);
    response.status(200).json({
      data: null,
      message: "User has been deleted",
    });
  } catch (error) {
    next(error);
  }
};
