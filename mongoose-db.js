var mongoose = require('mongoose');
var cfenv = require("cfenv");
var secretManager = require('./service/secret-manager');
var Schema = mongoose.Schema;

var Todo = new Schema({
  content: Buffer,
  updated_at: Date,
});

mongoose.model('Todo', Todo);

var User = new Schema({
  username: String,
  password: String,
});

mongoose.model('User', User);

// CloudFoundry env vars
var mongoCFUri = cfenv.getAppEnv().getServiceURL('goof-mongo');

// Default Mongo URI is local
const DOCKER = process.env.DOCKER;
var mongoUri = DOCKER === '1'
  ? 'mongodb://goof-mongo/express-todo'
  : 'mongodb://localhost/express-todo';

if (mongoCFUri) {
  mongoUri = mongoCFUri;
}

mongoose.connect(mongoUri);

User = mongoose.model('User');
User.find({ username: 'admin@snyk.io' }).exec(function (err, users) {
  if (!err && users && users.length === 0) {
    // Load admin seed password from Google Secret Manager via ADC
    secretManager.accessSecretVersion('nodejs-goof-admin-password').then(function (adminSecret) {
      new User({ username: 'admin@snyk.io', password: adminSecret }).save(function (saveErr) {
        if (saveErr) {
          console.log('error saving admin user');
        }
      });
    });
  }
});
