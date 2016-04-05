var crypto = require('crypto');
const algorithm = 'aes-128-ecb';



function encrypt(password, plaintext){
  var key = createKey(password);
  console.log("keyy:" + key);
  var iv = new Buffer('1234567812345678');
    var cipher = crypto.createCipheriv(algorithm, key, iv);
    cipher.setAutoPadding(true);
    var cipherText = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return cipherText;
}

function decrypt(password, cipherText){
  var key = createKey(password);
  console.log("keyy:" + key);
  var iv = new Buffer('1234567812345678');
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
/*
var plainText = new Buffer("odvoji fileove da bude strukturaodvoji fileove da bude struktura", "utf8");
console.log("plaintext:", plainText.toString("utf8"));

var key = "password";
var iv = new Buffer('');

console.log("key:", key);
console.log("iv:", iv.toString());

var cipherText = encrypt(key,plainText);
console.log("cipherText:", cipherText.toString("utf8"));
console.log("cipherText length: ", cipherText.length);

console.log("==========   decrypt     =============")
var decipherText = decrypt(key,cipherText);
console.log("decipherText:", decipherText.toString("utf8"));
console.log("decipherText length: ", decipherText.length);
*/