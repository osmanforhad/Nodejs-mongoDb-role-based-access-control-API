const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");

/**
 * Route for
 *
 * User SignUp
 */
router.post("/signup", userController.signup);
/**
 * Route for
 *
 * User Login
 */
router.post("/login", userController.login);

/**
 * Route for
 *
 * Show Single User
 */
router.get(
  "/user/:userId",
  userController.allowIfLoggedin,
  userController.getUser
);

/**
 * Route for
 *
 * Sow All Users
 */
router.get(
  "/users",
  userController.allowIfLoggedin,
  userController.grantAccess("readAny", "profile"),
  userController.getUsers
);

/**
 * Route for
 *
 * Update User info
 */
router.put(
  "/user/:userId",
  userController.allowIfLoggedin,
  userController.grantAccess("updateAny", "profile"),
  userController.updateUser
);

/**
 * Route for
 *
 * Delete a User
 */
router.delete(
  "/user/:userId",
  userController.allowIfLoggedin,
  userController.grantAccess("deleteAny", "profile"),
  userController.deleteUser
);

module.exports = router;
