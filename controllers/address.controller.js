const Address = require("../model/address.model");
const ApiResponse = require("../utils/ApiResponse");
const asyncHandler = require("../utils/asyncHandler");
const ApiError = require("../utils/ApiError");

const addAnAddress = asyncHandler(async (req, res) => {
  console.log("username: ", req.user.username);
  console.log(req.body);
  // Get address etails from frontend
  let userId = req.user._id;
  //Get address etails from frontend
  let {
    name,
    phoneNo,
    alternatePhoneNo,
    landmark,
    pinCode,
    locality,
    address,
    city,
    state,
    country,
  } = req.body;

  // Check for empty required fields
  const isEmpty = [
    name,
    phoneNo,
    pinCode,
    // locality,
    // address,
    // city,
    // state,
    // country,
  ].some((fields) => fields === undefined || fields.trim() === "");

  if (isEmpty) {
    throw new ApiError(400, "Please input the required fields");
  }

  // Check for invalid fields
  //   let invalidFields = [];
  //   name = validateName(name) || invalidFields.push("name");
  //   phoneNo = validatePhoneNo(phoneNo) || invalidFields.push("phoneNo");
  //   alternatePhoneNo =
  //     validatePhoneNo(alternatePhoneNo) || invalidFields.push("alternatePhoneNo");
  //   pinCode = validatePinCode(pinCode) || invalidFields.push("pinCode");

  //   if (invalidFields.length) {
  //     throw new ApiError(
  //       400,
  //       `Please enter the proper format!! Invalid field(s): ${invalidFields.join(
  //         ", "
  //       )}`
  //     );
  //   }

  const newAddress = await Address.create({
    userId,
    name,
    phoneNo,
    pinCode,
    city,
    addressState: state,
    country,
    landmark,
    address,
  });

  console.log(`Address updated successfully to the user ${userId}`);

  res
    .status(200)
    .json(new ApiResponse(200, newAddress, "Address added successfully"));
});

const getUserAddresses = asyncHandler(async (req, res) => {
  const userId = req.user._id;

  if (!userId) {
    ApiResponse(401, "Unauthorised User");
  }

  const addresses = await Address.find({ userId }).select(
    "-createdAt -updatedAt -userId"
  );

  console.log("Addresses fetched successfully");

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        addresses,
        `All addresses for user ${req.user.name} fetched successfully`
      )
    );
});

const updateAnAddress = asyncHandler(async (req, res) => {
  const addressId = req.params.id;
  // Check if incoming address belongs to loggedin user.
  // 1.) Find userId of the incoming address from params
  // 2.) Match this userId with userId of loggedin user
  // 3.) If not match then throw error saying Address doesn't belongs to this user and hence can't update the address

  const addressUser = await Address.findById(addressId).select("userId");
  if (addressUser.userId.toString() !== req.user._id.toString()) {
    throw new ApiError(
      403,
      "Address doesn't belongs to this user and hence can't update the address"
    );
  }

  console.log(req.params);
  const address = await Address.findByIdAndUpdate(addressId, req.body, {
    new: true,
  });
  console.log("Address updated successfully");
  res
    .status(200)
    .json(new ApiResponse(200, address, "Address updated successfully"));
});

const deleteAnAddress = asyncHandler(async (req, res) => {
  const addressId = req.params.id;

  const addressUser = await Address.findById(addressId).select("userId");
  if (addressUser.userId.toString() !== req.user._id.toString()) {
    throw new ApiError(
      403,
      "Address doesn't belongs to this user and hence can't delete the address"
    );
  }

  const address = await Address.findByIdAndDelete(addressId);
  console.log("Address deleted successfully");
  res
    .status(200)
    .json(new ApiResponse(200, address, "Address deleted successfully"));
});

module.exports = {
  addAnAddress,
  getUserAddresses,
  updateAnAddress,
  deleteAnAddress
};
