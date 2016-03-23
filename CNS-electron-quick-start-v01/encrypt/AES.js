var crypto = require('crypto');
const algorithm = 'aes-128-ecb';

function encrypt(key, iv, plaintext){
    var cipher = crypto.createCipheriv(algorithm, key, iv);
    cipher.setAutoPadding(false);
    var cipherText = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return cipherText;
}

function decrypt(key, iv, cipherText){
    var decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAutoPadding(false);
    var plainText = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    return plainText;
}

function createKey(password){
    //var key = crypto.randomBytes(16);
    
    var salt = "fixed";
    var salt = crypto.randomBytes(16);
    //crypto.pbkdf2Sync(password, salt, numOfIterationsOfFunc, outputSize, Func)
    var key = crypto.pbkdf2Sync(password, salt, 60000, 16, 'sha256');
    
    return key;
}



var plainText = new Buffer("odvoji fileove da bude strukturaodvoji fileove da bude struktura", "utf8");
console.log("plaintext:", plainText.toString("utf8"));

var key = createKey("password");
var iv = new Buffer('');

console.log("key:", key);
console.log("iv:", iv.toString());

var cipherText = encrypt(key,iv,plainText);
console.log("cipherText:", cipherText.toString("utf8"));
console.log("cipherText length: ", cipherText.length);

var decipherText = decrypt(key,iv,cipherText);
console.log("decipherText:", decipherText.toString("utf8"));
console.log("decipherText length: ", decipherText.length);