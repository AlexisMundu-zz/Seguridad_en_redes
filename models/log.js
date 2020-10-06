const mongoose = require('mongoose');

const LogSchema = new mongoose.Schema({
    timestamp: Date,
    username: String,
    user_id: mongoose.Types.ObjectId
  }, {collection: 'log'});

module.exports = mongoose.model('log', LogSchema);