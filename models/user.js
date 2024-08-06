// models/user.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  openaiApiKey: { type: String } // Add the OpenAI API key field
});

UserSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 8);
  }
  if (this.isModified('openaiApiKey')) {
    this.openaiApiKey = this.encryptApiKey(this.openaiApiKey)
  }
  next();
});

// Method to encrypt the OpenAI API key
UserSchema.methods.encryptApiKey = function(apiKey) {
  const cipher = crypto.createCipher('aes-256-cbc', process.env.JWT_SECRET);
  let encrypted = cipher.update(apiKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
};

// Method to decrypt the OpenAI API key
UserSchema.methods.decryptApiKey = function(encryptedApiKey) {
  const decipher = crypto.createDecipher('aes-256-cbc', process.env.JWT_SECRET);
  let decrypted = decipher.update(encryptedApiKey, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

module.exports = mongoose.model('User', UserSchema);
