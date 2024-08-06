require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/user'); // Adjust the path as necessary

// Connect to the MongoDB database
mongoose.connect(process.env.MONGO_URI, {
    dbName: "demandeai",
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const email = process.argv[2];
const newPassword = process.argv[3];

if (!email || !newPassword) {
  console.error('Usage: node changePassword.js <email> <newPassword>');
  process.exit(1);
}

async function changeUserPassword(email, newPassword) {
  try {
    const user = await User.findOne({ username: email });
    if (!user) {
      console.error('User not found');
      process.exit(1);
    }

    user.password = newPassword;
    await user.save();
    console.log('Password updated successfully');
    process.exit(0);
  } catch (error) {
    console.error('Error updating password:', error);
    process.exit(1);
  }
}

changeUserPassword(email, newPassword);
