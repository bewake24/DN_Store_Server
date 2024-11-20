const ApiResponse = require("../utils/ApiResponse");
const User = require("../model/user.model");
const asyncHandler = require("../utils/asyncHandler");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const ROLES_LIST = require("../config/rolesList");
const rolesObjectToArray = require("../utils/rolesObjectToArray");
const {
  MONGOOSE_VALIDATION_ERROR,
  MONGOOSE_DUPLICATE_KEY,
} = require("../constants/models.constants");
const invalidFieldMessage = require("../utils/invalidFieldMessage");

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false }); //didn't run validation to save the user here it will not ask for password.
    return { accessToken, refreshToken };
  } catch (error) {
    ApiResponse.error(
      res,
      "Error while generating access and refresh token",
      500
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  try {
    let { username, password, name, email, phoneNo, gender } = req.body;

    let userAvatar;
    if (req.file) {
      userAvatar = req.file?.filename;
    }

    // create user object & entry in DB
    const user = await User.create({
      name,
      username,
      password,
      email,
      phoneNo,
      gender,
      avatar: userAvatar,
    });

    const createdUser = await User.findById(user._id)
      .select("-password -refreshToken -addresses")
      .lean();

    if (!createdUser) {
      ApiResponse.error(res, "Error while registering the user.", 500);
    }
    ApiResponse.success(
      res,
      "User added successfully",
      rolesObjectToArray(createdUser),
      201
    );
  } catch (err) {
    if (err.code === MONGOOSE_DUPLICATE_KEY) {
      return ApiResponse.conflict(
        res,
        "User with this username or email already Exists.",
        409
      );
    }

    if (err.name === MONGOOSE_VALIDATION_ERROR) {
      return ApiResponse.validationError(
        res,
        "User validation failed.",
        invalidFieldMessage(err),
        400
      );
    }
    return ApiResponse.error(res, err.message, 500, err);
  }
});

const loginUser = asyncHandler(async (req, res) => {
  // Get data vaidated data from frontend
  let { usernameOrEmail, password } = req.body;

  // Find user
  const user = await User.findOne({
    $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
  }).exec();

  // Match User
  if (!user) {
    return ApiResponse.notFound(res, "User not found", 404);
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    return ApiResponse.unauthorized(res, "Password didn't matched", 401);
  }

  // Send response back
  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id
  );
  const loggedInUser = await User.findById(user._id)
    .select("-refreshToken")
    .lean();
  const options = {
    httpOnly: true,
    secure: true,
  };
  console.log(loggedInUser.name + " Loggedin Successefully");

  res
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options);

  return ApiResponse.success(
    res,
    {
      user: rolesObjectToArray(loggedInUser),
      accessToken,
      refreshToken,
    },
    "User logged In Successfully",
    200
  );
});

const logout = asyncHandler(async (req, res) => {
  // Remove remove user credentials from Db
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: {
        refreshToken: 1, // remove the field from DB completely
      },
    },
    {
      new: true, // Returns the updated value in response
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  // Save data in cookie
  res.cookie("accessToken", "", options).cookie("refreshToken", "", options);

  //Send response back

  ApiResponse.success(res, "User logged out successfully", {}, 200);
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken; // req.body.refreshToken -> If user is sending data from moblie application
  if (!incomingRefreshToken) {
    ApiResponse.unauthorized(res, "Unauthorised request");
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken?._id);

    if (!user) {
      ApiResponse.unauthorized(res, "Invalid Refresh token");
    }

    if (incomingRefreshToken !== user?.refreshToken) {
      ApiResponse.unauthorized(res, "Token expired or used");
    }

    const { accessToken, newRefreshToken } =
      await generateAccessAndRefreshToken(user._id);
    console.log(accessToken);
    console.log(newRefreshToken);

    const options = {
      httpOnly: true,
      secure: true,
    };

    console.log("New Tokens Generated Successfully");
    res
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options);

    ApiResponse.success(
      res,
      {
        accessToken,
        refreshToken: newRefreshToken,
      },
      "New Tokens generated succesfully",
      200
    );
  } catch (error) {
    ApiResponse.unauthorized(res, "Invalid Refresh token sent");
  }
});

const updateUserInfo = asyncHandler(async (req, res) => {
  try {
    let updates = req.body;
    const allowedUpdates = ["name", "email", "gender", "phoneNo"];
    let fieldsToUpdate = {};

    Object.keys(updates).forEach((key) => {
      if (allowedUpdates.includes(key)) {
        fieldsToUpdate[key] = updates[key];
      }
    });

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      {
        $set: fieldsToUpdate,
      },
      {
        new: true,
        runValidators: true, // Run validation on update
      }
    ).lean();
    console.log("User updated successfully");
    ApiResponse.success(
      res,
      rolesObjectToArray(updatedUser),
      "User updated successfully",
      200
    );
  } catch (err) {
    if (err.code === MONGOOSE_DUPLICATE_KEY) {
      return ApiResponse.conflict(
        res,
        "New email already registered to another accountplease provide another email.",
        409
      );
    }
    if ((err.name = MONGOOSE_VALIDATION_ERROR)) {
      return ApiResponse.validationError(
        res,
        "User update failed due to invalid field provided",
        invalidFieldMessage(err),
        400
      );
    } else {
      ApiResponse.error(res, error.message, 500, error);
    }
  }
});

const updateAvatar = asyncHandler(async (req, res) => {
  // Get user from cookies
  const user = await User.findById(req.user._id);
  if (!user) {
    ApiResponse.notFound(res, "User not loggedin or found");
  }

  if (!req.file) {
    ApiResponse.validationError(
      res,
      "Avatar update failed",
      { avatar: "Avatar is required" },
      400
    );
  }

  //Find old avatar from DB
  let oldAvatarPath = "";
  const AVATAR_ROOT = path.resolve(__dirname, "..", "public", "uploads");
  if (user.avatar) {
    oldAvatarPath = path.resolve(
      AVATAR_ROOT,
      user.username,
      user.avatar
    );
  }

  // Save new Avatar to DB
  user.avatar = req.file?.filename;
  await user.save();

  // Delete old avatar from server
  if (oldAvatarPath.startsWith(AVATAR_ROOT) && fs.existsSync(oldAvatarPath)) {
    fs.unlink(oldAvatarPath, (err) => {
      if (err) {
        ApiResponse.error(res, "Failed to delete old avatar", 500, err);
      }
    });
  }
  ApiResponse.success(res, user, "User avatar updated successfully", 200);
});

const updateUsername = asyncHandler(async (req, res) => {
  const incomingUsername = req.body.username;
  const oldUsername = req.user?.username;
  // Get user from cookies
  console.log(req.user?.username);

  if (!req.user?._id) {
    ApiResponse.notFound(res, "User not loggedin or not found");
  }

  if (oldUsername === incomingUsername) {
    ApiResponse.forbidden(
      res,
      "New username can't be same as current username"
    );
  }

  const user = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: { username: incomingUsername },
    },
    {
      new: true,
      runValidators: true, // Run validation on update
    }
  ).lean();
  console.log("User updated successfully");

  // Rename folder for user according to the new username
  const oldPath = path.join(__dirname, "..", "public", "uploads", oldUsername);
  console.log(oldPath);
  const newPath = path.join(
    __dirname,
    "..",
    "public",
    "uploads",
    incomingUsername
  );

  fs.rename(oldPath, newPath, (err) => {
    if (err) {
      console.log(err);
    } else {
      console.log("Successfully renamed the directory.");
    }
  });

  ApiResponse.success(
    res,
    "User updated successfully",
    rolesObjectToArray(user),
    200
  );
});

const getAllUsers = asyncHandler(async (req, res) => {
  let users = await User.find().select("roles username").lean();
  users = rolesObjectToArray(users);
  ApiResponse.success(res, "All users fetched", users, 200);
});

const getUsersByRole = asyncHandler(async (req, res) => {
  const roles = req.query.roles ? req.query.roles.toUpperCase().split(",") : [];
  const numericRoles = roles
    .map((role) => ROLES_LIST[role])
    .filter((role) => role !== undefined);

  if (!numericRoles.length) {
    return res.status(400).json({ message: "Invalid roles provided" });
  }

  const users = await User.find({
    $or: numericRoles.map((roleValue) => ({
      [`roles.${Object.keys(ROLES_LIST).find(
        (key) => ROLES_LIST[key] === roleValue
      )}`]: roleValue,
    })),
  })
    .select("roles username")
    .lean();
  ApiResponse.success(res, "All users fetched", rolesObjectToArray(users), 200);
});

module.exports = {
  registerUser,
  loginUser,
  logout,
  updateUsername,
  refreshAccessToken,
  updateUserInfo,
  updateAvatar,
  getAllUsers,
  getUsersByRole,
};

// Is it necessary to check for allowed updates while updating user?
