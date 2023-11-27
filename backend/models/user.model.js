const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, minlength: 5 },
  name: { type: String },
  gender: { type: String },
  address: { type: String },
  phoneNo: { type: String },
  role: { type: String },
  team: { type: String },
  objective: { type: String },
  skills: { type: String },
  doj: { type: String },
  notification: { type: Array },
  alert: { type: Array },
});

UserSchema.pre('save', async function (next) {
  try {
    const user = this;
    if (!user.isModified('password'))
      return next();

    const salt = await bcryptjs.genSalt(10);
    const secPassword = await bcryptjs.hash(user.password, salt);
    user.password = secPassword;
  } catch (error) {
    console.log(error.message);
    next();
  }
});

UserSchema.methods.generateToken = async function () {
  try {
    return jwt.sign(
      {
        userId: this._id.toString(),
        email: this.email
      },
      process.env.JWT_SECRET,
      { expiresIn: "10d" }
    )
  } catch (error) {
    console.log(error.message);
  }
}

UserSchema.methods.validatePassword = async function (password) {
  try {
    const res = await bcryptjs.compare(password, this.password);
    return res;
  } catch (error) {
    console.log(error.message);
  }
}

const User = mongoose.model("User", UserSchema);
module.exports = User;
