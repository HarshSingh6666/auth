const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email'],
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [6, 'Password must be at least 6 characters'],
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
  },
  { timestamps: true }
);

// ✅ SAHI TARIKA: Async function use karein BINA 'next' ke
userSchema.pre('save', async function () {
  // Agar password change nahi hua, toh yahin se return kar jao
  if (!this.isModified('password')) return;

  try {
    const salt = await bcrypt.getSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    // Yahan next() likhne ki zarurat nahi hai, async automatically handle kar lega
  } catch (error) {
    throw error; // Mongoose automatically is error ko catch kar lega
  }
});

// Compare password method
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', userSchema);