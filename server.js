const https = require('https'); 
const express = require('express');
const app = express();
const formidable = require('formidable'); 
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const router = express.Router();
const bodyParser = require('body-parser');
const expressSession = require('express-session')({
  secret: 'secret',
  resave: false,
  saveUninitialized: false
});
const mongoose = require('mongoose');
const passport = require('passport');
require('dotenv').config();

const User = require('./models/user');
const Log = require('./models/log');
const { use } = require('passport');

const NEXMO_KEY = process.env.NEXMO_KEY;
const NEXMO_SECRET = process.env.NEXMO_SECRET;

let privateKey, publicKey;


/////////////////////
// CONNECT MONGOOSE TO DB
const db_uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASS}@cluster0.8stah.mongodb.net/${process.env.DB_NAME}?retryWrites=true&w=majority`
mongoose.connect(db_uri,
  { useNewUrlParser: true, useUnifiedTopology: true }, (err) => {
    if(err) console.log('Connection Failed', err);
    else console.log('Connected to DB succesfully');
  }
);



app.use(expressSession);
app.use(express.static(path.join(__dirname, 'public')));
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

async function registerUserLogin(user){
  const new_log = new Log({timestamp: new Date(), user_id: user._id, username: user.username});
  await new_log.save();
  console.log("Login saved");
}

async function getLastLogin(user){
  const logs = await Log.find({user_id: user._id}).sort('-timestamp');
  return logs.length > 1 ? logs[1] : null;
}

router.post('/login',
  passport.authenticate('local', {failureRedirect: '/login'}),
  function(req, res){
    if(req.isAuthenticated()){
      registerUserLogin(req.user);
      res.redirect('/');
    }
  }
);

router.post('/register', function(req, res) {
  Users=new User({username: req.body.username});

  User.register(Users, req.body.password, function(err, user) {
    if (err) {
      console.log("Could not save new account. Error: ", err);
      res.redirect('/register');
    }else{
      console.log("Account has been saved");
      res.redirect('/');
    }
  });
});

app.get('/lastLogin', isLoggedIn, async function(req, res){
  const log = await getLastLogin(req.user);
  res.json({log: log});
})

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/login');
})

router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/html/login.html'));
})

router.get('/', isLoggedIn, async (req, res) => {
  res.sendFile(path.join(__dirname, 'public/html/index.html'));
})

router.post('/fileupload', (req, res) => {
    console.log('File uploaded!');
    let form = new formidable.IncomingForm();
    form.parse(req, function (err, fields, files) {
      let oldpath = files.filetoupload.path;
      let newpath = `${__dirname}/uploaded-files/${files.filetoupload.name}`;
      fs.rename(oldpath, newpath, function (err) {
        if (err) throw err;
        res.redirect('/');
        res.end();
      });
    });

})

router.post('/sign', (req, res) => {
  console.log("Sign Files");

  let keys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });

  privateKey = keys.privateKey;
  publicKey = keys.publicKey;
  let files = getFiles();

  for(file of files){
    const sign = crypto.createSign('SHA256');
    let data = fs.readFileSync(`${__dirname}/uploaded-files/${file}`)
    sign.update(data);
    sign.end();
    const signature = sign.sign(privateKey, 'hex');
    fs.writeFile(`${__dirname}/signed-files/${file}`, signature, () => {});
  }
  res.redirect('/');
})

router.post('/verify', (req, res) => {
  console.log("Verify Files");
  let files = getFiles();
  for(file of files){
    const data = fs.readFileSync(`${__dirname}/uploaded-files/${file}`)
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    const signature = fs.readFileSync(`${__dirname}/signed-files/${file}`).toString();
    let verification_result = verify.verify(publicKey, signature, 'hex');
    console.log(file, verification_result);
    if(!verification_result) {
      res.write(`Verification failed for ${file}`, function(err) { res.end(); });
      return;
    }
  }

  res.write('Verification succeded for all files');
  res.end();
})


router.get('/files', (req, res) => {
  let files = getFiles();
  res.json({'files': files})
})

function getFiles(){
  let files = [];
  fs.readdirSync(`${__dirname}/uploaded-files`).forEach(file => {
    files.push(file)
  });
  return files;
}

router.get('/edit', isLoggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, '/public/html/edit.html'));
})

router.post('/edit', async (req, res) => {
  if(req.body.user.oldPass && req.body.user.newPass)
    await req.user.changePassword(req.body.user.oldPass, req.body.user.newPass).catch(error => res.send('Could not update password: incorrect old password'));
  if(req.body.user.username && req.body.user.username != req.user.username){
    User.findById(req.user._id, (err, doc) => {
      if(err)
        return res.send('Something went wrong, try again later.')
      doc.username = req.body.user.username;
      doc.save();
    })
  }
  return res.send('Profile updated');
})

router.get('/user', isLoggedIn, (req, res) => {
  res.json(req.user);
  res.end()
})


app.use('/', router);

const options = {
    key: fs.readFileSync('server.key'), cert: fs.readFileSync('server.cert')
};

function isLoggedIn(req, res, next){
  // return next();
  if(req.isAuthenticated()){
    return next();
  }
  res.redirect('/login');
}

https.createServer(options, app).listen(3000, () => { console.log('Server running at https://127.0.0.1:3000/')
})