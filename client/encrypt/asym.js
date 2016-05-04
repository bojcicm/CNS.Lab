/**
 * https://en.wikibooks.org/wiki/Cryptography/Generate_a_keypair_using_OpenSSL 
 * 
 * https://etherhack.co.uk/asymmetric/docs/rsa_key_breakdown.html
 * 
 * private_key.pem includes the modulus (also referred to as public key and n), 
 * public exponent (also referred to as e and exponent; default value is 0x010001), 
 * private exponent, and primes used to create keys (prime1, also called p, and prime2, also called q), 
 * a few other variables used to perform RSA operations faster, 
 * and the Base64 PEM encoded version of all that data.
 * 
 */

/**
 * 1. Generate_a_keypair_using_OpenSSL (encrypted with aes-128)
 *    openssl genpkey -aes128 -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048  
 * 
 * 2. Extract public_key
 *    openssl rsa -pubout -in private_key.pem -out public_key.pem  
 * 
 * 3. Decrypt private_key
 *    openssl pkey -inform PEM -in private_key.pem -passin pass:password
 * 
 * 4. To print out the components of a private key to standard output:
 *    // https://www.openssl.org/docs/manmaster/apps/pkey.html
 *    openssl pkey -in key.pem -text -noout  
 * 
 */

const exec = require('child_process').exec;
const fs = require('fs');
const crypto = require('crypto');
const constants = require('constants');
const assert = require('assert');

// Get a password from as a cmd line argument and then the encrypted private_key
if ( process.argv.length == 3 ) {
    // Run this part as a closure to ensure password gets deleted once the function ends.
    (function() { 
        var password = process.argv[2];  
        var open_private_key = exec('openssl pkey -inform PEM -in ../../keys/private_key.pem -passin pass:' + password, function(err, out, stderr) {            
            if (err !== null) {
                console.log('exec error: ' + err);
                return;
            }
            var private_key = out;
            
            // Use the loaded asymmetric keys
            //testRSA(private_key);   
            //testRSA2(private_key);
            testDiffieHellman();
            //testDiffieHellman2();
            //graphDiffieHellman();         
        });
        password = "";                
    })();  		
} else {
	console.log('Usage: node asym.js <password>');
	return;
}

function testRSA(_private_key) {
    //console.log(_private_key);
    
    // Short message (m < N)
    var plaintext = "Poruka koja je enkriptirana sa public encryptom. Valjda radi?";
    console.log("plaintext:", plaintext);
    
    // Long message (m > N)
    // error:0407906E:rsa routines:RSA_padding_add_PKCS1_OAEP:data too large for key size
    //plaintext = //"testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest";
    
    // NOTE: _private_key comprises the public_key as well and nodejs knows how to extract it from the _private_key!!!
    var ciphertext = crypto.publicEncrypt( _private_key, new Buffer(plaintext, "utf8") ); 
    console.log("ciphertext:", ciphertext.toString("hex"));
    console.log("ciphertext length (bits):", ciphertext.toString("hex").length*4);

    var decrypted_plaintext = crypto.privateDecrypt(_private_key, ciphertext);
    console.log("decrypted:", decrypted_plaintext.toString("utf8"));    
    
}

/**
 * Testing different PADDING options.
 */ 
function testRSA2(_private_key) {    
    var plaintext;
     
    //=============================================================================================
    // Padding scheme: RSA_NO_PADDING
    // IMPORTANT: Not probabilistic scheme; same plaintext always results in the same ciphertext.
    //=============================================================================================    
    console.log("\nRSA_NO_PADDING");        
    // 2048 bits
    
    plaintext = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    
    console.log("plaintext:", plaintext);
    
    var ciphertext = crypto.publicEncrypt({ 
        key: _private_key,
        padding: constants.RSA_NO_PADDING
    }, new Buffer(plaintext, "utf8"));
    console.log("ciphertext:", ciphertext.toString("hex"));
    console.log("ciphertext length (bits):", ciphertext.toString("hex").length*4);

    var decrypted_plaintext = crypto.privateDecrypt({ 
        key: _private_key,
        padding: constants.RSA_NO_PADDING
    }, ciphertext);
    console.log("decrypted:", decrypted_plaintext.toString("utf8"));
    
    //=============================================================================================
    // Padding scheme: RSA_PKCS1_PADDING (PKCS #1 v1.5)
    //
    // IMPORTANT: PKCS #1 v1.5 is NOT secure; use PKCS#1 version 2.0 (i.e., RSA_PKCS1_OAEP_PADDING)
    //=============================================================================================    
    console.log("\nRSA_PKCS1_PADDING");        
    // 2048 bits
    plaintext = "00000";
    console.log("plaintext:", plaintext);
    
    ciphertext = crypto.publicEncrypt({ 
        key: _private_key,
        padding: constants.RSA_PKCS1_PADDING
    }, new Buffer(plaintext, "utf8"));
    console.log("ciphertext:", ciphertext.toString("hex"));
    console.log("ciphertext length (bits):", ciphertext.toString("hex").length*4);

    decrypted_plaintext = crypto.privateDecrypt({ 
        key: _private_key,
        padding: constants.RSA_PKCS1_PADDING
    }, ciphertext);
    console.log("decrypted:", decrypted_plaintext.toString("utf8"));    
    
    // This serves to check PKCS #1 v1.5 formating.
    decrypted_plaintext = crypto.privateDecrypt({ 
        key: _private_key,
        padding: constants.RSA_NO_PADDING
    }, ciphertext);
    console.log("decrypted RSA_PKCS1_PADDING/RSA_NO_PADDING:", decrypted_plaintext.toString("hex"));    
   
   
    //=============================================================================================
    // Padding scheme: RSA_PKCS1_OAEP_PADDING (PKCS #1 v2.0)
    //
    // IMPORTANT: RSA_PKCS1_OAEP_PADDING is secure and a default padding scheme in Node.js.
    //=============================================================================================    
    console.log("\nRSA_PKCS1_OAEP_PADDING");        
    // 2048 bits
    plaintext = "00001";
    console.log("plaintext:", plaintext);
    
    ciphertext = crypto.publicEncrypt({ 
        key: _private_key,
        padding: constants.RSA_PKCS1_OAEP_PADDING
    }, new Buffer(plaintext, "utf8"));
    console.log("ciphertext:", ciphertext.toString("hex"));
    console.log("ciphertext length (bits):", ciphertext.toString("hex").length*4);

    decrypted_plaintext = crypto.privateDecrypt({ 
        key: _private_key,
        padding: constants.RSA_PKCS1_OAEP_PADDING
    }, ciphertext);
    console.log("decrypted:", decrypted_plaintext.toString("utf8"));       
    
    console.log("\nLoading PUBLIC KEY");
    console.log(loadPublicKey('/../../keys/public_key.pem').toString());    
}


function loadPublicKey(pathToKey) { // relative to this script
    var _publicKey = fs.readFileSync(__dirname + pathToKey);
    return _publicKey;
}

function testDiffieHellman() {
     const Alice = crypto.getDiffieHellman('modp15');
     const Bob = crypto.getDiffieHellman('modp15');
      
     Alice.generateKeys();
     Bob.generateKeys();
     
     console.log("======================================");
     console.log("ALICE");
     console.log("======================================");
     console.log("g:", Alice.getGenerator('hex'), '\n');
     console.log("p:", Alice.getPrime('hex'), ' (' + Alice.getPrime('hex').length*4 + ')\n');
     console.log("private_key:", Alice.getPrivateKey('hex'), ' (' + Alice.getPrivateKey('hex').length*4 + ')\n');
     console.log("public_key:", Alice.getPublicKey('hex'), ' (' + Alice.getPublicKey('hex').length*4 + ')\n');
     
     console.log("======================================");
     console.log("BOB");
     console.log("======================================");
     console.log("g:", Bob.getGenerator('hex'), '\n');
     console.log("p:", Bob.getPrime('hex'), ' (' + Bob.getPrime('hex').length*4 + ')\n');
     console.log("private_key:", Bob.getPrivateKey('hex'), ' (' + Bob.getPrivateKey('hex').length*4 + ')\n');
     console.log("public_key:", Bob.getPublicKey('hex'), ' (' + Bob.getPublicKey('hex').length*4 + ')\n');
     
     const alice_secret = Alice.computeSecret(Bob.getPublicKey(), null, 'hex');
     const bob_secret = Bob.computeSecret(Alice.getPublicKey(), null, 'hex');
     
     console.log("======================================");
     console.log("SECRET KEYS K_AB & K_BA");
     console.log("======================================");     
     console.log("Secret K_AB:", alice_secret, '\n');
     console.log("Secret K_BA:", bob_secret, '\n');
     
     // Test equality
     assert.strictEqual(alice_secret, bob_secret);    
     
     // Generate 128-bit AES key
     crypto.pbkdf2(alice_secret, 'Alice and Bob', 1, 16, 'sha512', function(err, key){
        if (err) throw err;
        console.log("Secret key (128 bits):", key.toString('hex'));
     });                      
}

function testDiffieHellman2() {
     
    var parties = {Alice: null, 
                   Bob: null, 
                   Mirko: null, 
                   Slavko: null};
     
    var users = Object.keys(parties),
            len = users.length,
            i = 0,
            user;
    while (i < len) {
        user = users[i];
        parties[user] = crypto.getDiffieHellman('modp15');
        parties[user].generateKeys();
        console.log('Generated DH keys for', user);         
        i +=1;
    }                   

    // Generate pairwise AES keys...
    var users_out = Object.keys(parties),
            i_out = 0,
            user_out;
    console.log();                
    while (i_out < len) {                
        i = 0;
        user_out = users_out[i_out];
        
        while (i < len) {
            user = users[i];        
            if (user !== user_out) {
                var DH_secret_key = parties[user_out].computeSecret(parties[user].getPublicKey(), null, 'hex');
                
                // Generate 128-bit AES keys
                (function() {                    
                    var _user_out = user_out,
                        _user = user;    
                    crypto.pbkdf2(DH_secret_key, 'salt', 1, 16, 'sha512', function(err, key){                                
                        if (err) throw err;
                        console.log("K_" + _user_out.slice(0,1) + _user.slice(0,1) + ':', key.toString('hex'));                
                    });
                })();
            }         
            i +=1;
        }        
        i_out +=1;
    }        
}


function graphDiffieHellman() {
    var fs = require('fs'),
        dir = 'DH',
        filename = 'DiffieHellmanKeys.txt';
        
    try {	
        if ( !fs.existsSync( 'DH' ) ) fs.mkdirSync( 'DH' );
    } catch (e) {  
        console.err(e);
    }        
                
    file = fs.createWriteStream( dir + '/' + filename, {defaultEncoding: 'utf8'} );    

    const Alice = crypto.createDiffieHellman(6);
    var p, g;
          
    Alice.generateKeys();   
    p = parseInt('0x' + Alice.getPrime('hex'),'hex');
    g = parseInt('0x' + Alice.getGenerator('hex'),'hex');
    
    console.log("g:", g);
    console.log("p:", p);
    
    
    
    var N = 100,
        private_keys = [],
        private_keys_hex = [],
        public_keys = []; 
           
    // Generate N private DH keys randomly (xs)
    for (var i=0; i < 1000000; i++) {
        var _num_hex = crypto.randomBytes(2).toString('hex');
        var _num = parseInt('0x' + _num_hex, 'hex');        
        if (2 < _num && _num < p-2) {
            private_keys_hex.push(_num_hex);
            private_keys.push(_num);                
        }
        if (private_keys.length >= N) break;
    }           
           
    for (var i=0, len = private_keys.length; i < len; i++) {        
        Alice.setPrivateKey(private_keys_hex[i], "hex");
        Alice.generateKeys();
        public_keys[i] = parseInt('0x' + Alice.getPublicKey('hex'),'hex');
    }    
    
    file.write('private_keys = [' + private_keys + ']; \n');
    file.write('public_keys = [' + public_keys + ']; \n');
    file.end();        
}