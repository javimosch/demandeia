const mongoose = require('mongoose');

const PresentSchema = new mongoose.Schema({
  label: String,
  presetJson: String,
  formConfig: String,
  messageTemplate: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

module.exports = mongoose.model('Preset', PresentSchema);
