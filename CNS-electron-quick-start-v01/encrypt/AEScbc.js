var crypto = require('crypto');
const algorithm = 'aes-128-ctr';



function encrypt(password, plaintext, iv){
  var key = createKey(password);
  console.log("keyy:" + key);
    var cipher = crypto.createCipheriv(algorithm, key, iv);
    cipher.setAutoPadding(true);
    var cipherText = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return cipherText.toString("hex");
}

function decrypt(password, cipherText, iv){
  var key = createKey(password);
  console.log("keyy:" + key);
  var decipher = crypto.createDecipheriv(algorithm, key, iv);
  
  decipher.setAutoPadding(true);
  var plainText = Buffer.concat([decipher.update(cipherText), decipher.final()]);
  
  return plainText;
}

function createKey(password){
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