const roles = require("../roles");
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

//__Method for get all Users__//
exports.getUsers = async (request, response, next) => {
  const users = await User.find({});
  response.status(200).json({
    data: users,
  });
};

//__Method for get single User Details__//
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

//__Method for Update User__//
exports.updateUser = async (request, response, next) => {
  try {
    const update = request.body;
    const userId = request.params.userId;
    await User.findByIdAndUpdate(userId, update);
    const user = await User.findById(userId);
    response.status(200).json({
      data = user,
      message: "User has been updated"
    });
  } catch (error) {
    next(error)
  }
};

//__Method for Delete Single User__//
exports.deleteUser = async(request, response, next) => {
  try {
    const userId = request.params.userId;
    await User.findByIdAndDelete(userId);
    response.status(200).json({
      data:null,
      message: "Usr has been Deleted"
    })
  } catch (error) {
    next(error)
  }
}

//__Method for AccessControl__//
exports.grantAccess = function(action, resource) {
  return async (request, response, next) => {
    try {
      const permission = roles.can(request.user.role)[action](response);
      if(!permission.granted) {
        return response.status(401).json({
          error: "You dont have enough permission to perform this action"
        });
      }
      next();
    } catch (error) {
      next(error)
    }
  }
}

//__Method for Check User Logged in Functionality__//
exports.allowIfLoggedin = async (request, response, next) => {
  try {
    const user = response.locals.loggedInUser;
    if(!user)
    return response.status(401).json({
      error: "You need to be logged in to access this route"
    });
    request.user = user;
    next();
  } catch (error) {
    next(error);
  }
}
