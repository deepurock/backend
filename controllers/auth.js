import User from "../models/User.js";
import bcrypt from "bcryptjs";
import { createError } from "../utils/error.js";
import jwt from "jsonwebtoken";

export const register = async (req, res, next) => {
  try {
    const salt = await bcrypt.genSalt(10);
    const newUser = new User({
      // userName: req.body.userName,
      // email: req.body.email,
      ...req.body,
      password: await bcrypt.hash(req.body.password, salt),
    });
    await newUser.save();
    res.status(201).send("User has been created");
  } catch (error) {
    next(error);
  }
};

export const login = async (req, res, next) => {
  try {
    const user = await User.findOne({ userName: req.body.username });
    if (!user) return next(createError(404, "user not found"));

    const isPasswordCorrect = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!isPasswordCorrect)
      return next(createError(400, "wrong password or username"));

    let access_token = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT
    );
    const { password, isAdmin, ...otherDetails } = user._doc;
    // res.status(200).json({ ...otherDetails, access_token });
    res
      .cookie("access_token", access_token, {
        httpOnly: true,
      })
      .status(200)
      .json({
        details: { ...otherDetails, access_token },
        isAdmin,
        access_token,
      });
  } catch (error) {
    next(error);
  }
};
