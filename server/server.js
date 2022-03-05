const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const path = require("path");
const User = require("./models/userModel");
const routes = require("./routes/route.js");
require("dotenv").config({
  path: path.join(__dirname, "../.env"),
});

const app = express();

const PORT = process.env.PORT || 3000;

mongoose
  .connect("mongodb://localhost:27017/rbac", { useNewUrlParser: true })
  .then(() => {
    console.log("Connected to the Database successfully");
  });

app.use(bodyParser.urlencoded({ extended: true }));

app.use(async (request, response, next) => {
  if (request.headers["x-access-token"]) {
    try {
      const accessToken = request.headers["x-access-token"];
      const { userId, exp } = await jwt.verify(
        accessToken,
        process.env.JWT_SECRET
      );
      // If token has expired
      if (exp < Date.now().valueOf() / 1000) {
        return response.status(401).json({
          error: "JWT token has expired, please login to obtain a new one",
        });
      }
      response.locals.loggedInUser = await User.findById(userId);
      next();
    } catch (error) {
      next(error);
    }
  } else {
    next();
  }
});

app.use("/", routes);

app.listen(PORT, () => {
  console.log("Server is listening on Port:", PORT);
});
