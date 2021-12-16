const crypto = require('crypto');

let ENCODING = 'hex';
let KEY_SIZE = 256;
let ELEMENT_SIZE = 32;

/**
 *
 * @param {Integer} elementSize
 * @returns
 */
function randomString(elementSize) {
     return crypto.randomBytes(elementSize).toString(ENCODING);
}

/**
 *
 * @param {Integer} n
 * @returns
 */
function randomPrivateKey(keySize, elementSize) {
     let priv = [];
     for (i = 0; i < keySize; i++) {
          priv.push(randomString(elementSize));
     }
     return priv;
}

/**
 * Hash and return hex
 *
 * @param {String} str
 * @returns string
 */
function hash(str) {
     return crypto.createHash('sha256').update(str).digest(ENCODING);
}

/**
 *
 * @param {String} str
 * @returns
 */
function stringToBinaryArray(str) {
     let stringBuffer = Buffer.from(str, ENCODING);
     let binaryArray = [];
     stringBuffer.forEach(byte => {
          for (let i = 7; i >= 0; i--) {
               binaryArray.push((byte >> i) & 1);
          }
     });
     return binaryArray;
}

/**
 *
 * @param {Array} rawSignature
 * @returns
 */
function encodeSignatureToBuffer(rawSignature) {
     let bufferArray = [];
     for (let item of rawSignature) {
          bufferArray.push(Buffer.from(item, ENCODING));
     }
     return Buffer.concat(bufferArray);
}

/**
 *
 * @param {Array} signatureRaw
 * @returns
 */
function encodeSignature(signatureRaw) {
     return encodeSignatureToBuffer(signatureRaw).toString(ENCODING);
}

/**
 *
 * @param {String} encodeSignature
 * @returns
 */
function decodeSignature(encodeSignature) {
     let stringBuffer = Buffer.from(encodeSignature, ENCODING);
     let signatureArray = [];
     for (let i = 0; i < KEY_SIZE; i++) {
          let offset = i * ELEMENT_SIZE;
          let bufferItem = stringBuffer.slice(offset, offset + ELEMENT_SIZE);
          signatureArray.push(bufferItem.toString(ENCODING));
     }
     return signatureArray;
}

/**
 *
 * @param {Array} keyRaw
 * @returns
 */
function encodeKey(keyRaw) {
     let keyArray = [];
     for (let partKey of keyRaw) {
          for (let item of partKey) {
               keyArray.push(Buffer.from(item, ENCODING));
          }
     }
     let keyBuffer = Buffer.concat(keyArray);
     return keyBuffer.toString(ENCODING);
}

/**
 *
 * @param {String} encodeKey
 * @returns
 */
function decodeKey(encodeKey) {
     let stringBuffer = Buffer.from(encodeKey, ENCODING);
     let firstKey = [];
     let secondKey = [];
     let key = [
          firstKey,
          secondKey
     ];
     for (let i = 0; i < KEY_SIZE; i++) {
          let offset = i * ELEMENT_SIZE;
          let bufferItem = stringBuffer.slice(offset, offset + ELEMENT_SIZE);
          firstKey.push(bufferItem.toString(ENCODING));
     }
     let totalLenght = KEY_SIZE * 2;
     for (let i = KEY_SIZE; i < totalLenght; i++) {
          let offset = i * ELEMENT_SIZE;
          let bufferItem = stringBuffer.slice(offset, offset + ELEMENT_SIZE);
          secondKey.push(bufferItem.toString(ENCODING));
     }
     return key;
}

/**
 *
 * @param {String} signature
 * @param {String} publicKey
 * @param {String} message
 * @returns
 */
function verify(signature, publicKey, message) {
     let messageHash = hash(message);
     let messageBinary = stringToBinaryArray(messageHash);
     let dSignature = decodeSignature(signature);
     let dPublicKey = decodeKey(publicKey);

     return messageBinary.every((bit, index) => {
          let hashSignature = hash(dSignature[index]);
          let publicKeyitem = dPublicKey[bit][index];
          return hashSignature === publicKeyitem;
     });
}

function main() {

     let message = 'Hello cryptocurrency';

     let privateKeyRaw = [
          randomPrivateKey(KEY_SIZE, ELEMENT_SIZE),
          randomPrivateKey(KEY_SIZE, ELEMENT_SIZE)
     ]

     let publicKeyRaw = privateKeyRaw.map(privateKeyPart => privateKeyPart.map(priv => {
          return hash(priv);
     }));

     console.log("==== Private key (keep secret) =====");
     console.log("Priv[0][0] (Set A) ", privateKeyRaw[0][0]);
     console.log("Priv[0][1] (Set A) ", privateKeyRaw[0][1]);
     console.log("Priv[0][2] (Set A) ", privateKeyRaw[0][2]);
     console.log("Priv[0][3] (Set A) ", privateKeyRaw[0][3]);
     console.log("Priv[1][0] (Set B) ", privateKeyRaw[1][0]);
     console.log("Priv[1][1] (Set B) ", privateKeyRaw[1][1]);
     console.log("Priv[1][2] (Set B) ", privateKeyRaw[1][2]);
     console.log("Priv[1][3] (Set B) ", privateKeyRaw[1][3]);


     console.log("==== Public key (show everyone)=====");
     console.log("Pub[0][0] (Set A) ", publicKeyRaw[0][0]);
     console.log("Pub[0][1] (Set A) ", publicKeyRaw[0][1]);
     console.log("Pub[1][0] (Set B) ", publicKeyRaw[1][0]);
     console.log("Pub[1][1] (Set B) ", publicKeyRaw[1][1]);
     message = message.toString("utf8");

     console.log("===== Encode Key ===================");
     let publicKey = encodeKey(publicKeyRaw);
     let privateKey = encodeKey(privateKeyRaw);

     console.log("==== Message to sign ===============");
     let messageHash = hash(message);

     console.log("Message: ", message);
     console.log("SHA265: ", messageHash);

     console.log("==== Signature =====================");

     let messageBinary = stringToBinaryArray(messageHash);
     let signatureRaw = messageBinary.map((bit, index) => {
          return privateKeyRaw[bit][index];
     });
     let signature = encodeSignature(signatureRaw);
     console.log("Signature: ", signature);


     console.log("==== Verify ========================");
     let isVerify = verify(signature, publicKey, message);
     console.log(isVerify);
}

main();