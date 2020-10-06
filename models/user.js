const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');

const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
    secret_2fa: String
  }, {collection: 'user'});

UserSchema.plugin(passportLocalMongoose);

module.exports = mongoose.model('user', UserSchema);