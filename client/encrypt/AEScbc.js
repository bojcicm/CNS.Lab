var crypto = require('crypto');
const algorithm = 'aes-128-cbc';



function encrypt(password, plaintext, iv) {
  var key = createKey(password);
  var cipher = crypto.createCipheriv(algorithm, key, iv);
  cipher.setAutoPadding(true);
  var ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  return ciphertext;
}

function decrypt(password, ciphertext, iv) {
  var key = createKey(password);
  var decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAutoPadding(true);
  var plaintext = decipher.update(ciphertext, 'hex', 'utf8');
  plaintext += decipher.final('utf8');
  return plaintext;
}

function createKey(password) {
  //var key = crypto.randomBytes(16);

  var salt = "fixed";
  console.log(salt);
  //crypto.pbkdf2Sync(password, salt, numOfIterationsOfFunc, outputSize, Func)
  var key = crypto.pbkdf2Sync(password, salt, 60000, 16, 'sha256');

  return key;
}


module.exports = {
  encrypt: encrypt,
  decrypt: decrypt,
  createKey: createKey
};