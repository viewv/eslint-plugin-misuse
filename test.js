crypto = require('node:crypto');

length = 4096;

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {modulusLength: length,});

console.log(publicKey, privateKey);


const data = "my secret data";

const encryptedData = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    // We convert the data string to a buffer using `Buffer.from`
    Buffer.from(data)
  );
  
// The encrypted data is in the form of bytes, so we print it in base64 format
// so that it's displayed in a more readable form
console.log("encypted data: ", encryptedData.toString("base64"));
