/**
 * @fileoverview Detect Github CryptoJS crypto misuse
 * @author viewv
 */
"use strict";

//------------------------------------------------------------------------------
// Requirements
//------------------------------------------------------------------------------

const rule = require("../../../lib/rules/github-cryptojs-misuse"),
  RuleTester = require("eslint").RuleTester;


//------------------------------------------------------------------------------
// Tests
//------------------------------------------------------------------------------

const ruleTester = new RuleTester();
ruleTester.run("github-cryptojs-misuse", rule, {
  valid: [
    // give me some code that won't trigger a warning
  ],

  invalid: [
    // {
    //   code: 'require("crypto-js/aes"); var hash = CryptoJS.SHA1("Message");',
    //   errors: [{ message: "SHA1 is not secure", type: "CallExpression" }],
    // },
    // {
    //   code: 'require("crypto-js/aes"); var hash = CryptoJS.MD5("Message");',
    //   errors: [{ message: "MD5 is not secure", type: "CallExpression" }],
    // },
    // {
    //   code: 'require("crypto-js/aes"); CryptoJS.HmacMD5("Message", "Secret Passphrase");',
    //   errors: [
    //     { message: "MD5 is not secure", type: "CallExpression" },
    //     { message: "Key should not be fixed", type: "CallExpression" }
    //   ],
    // },
    // {
    //   code: 'require("crypto-js"); CryptoJS.HmacSHA1("Message", "Secret Passphrase");',
    //   errors: [
    //     { message: "SHA1 is not secure", type: "CallExpression" },
    //     { message: "Key should not be fixed", type: "CallExpression" }
    //   ],
    // },
    // {
    //   code: 'require("crypto-js"); CryptoJS.PBKDF2("Secret Passphrase", salt, {keySize: 512 / 32, iterations: 1000});',
    //   errors: [
    //     { message: "Key should not be fixed", type: "CallExpression" }
    //   ],
    // },
    // {
    //   code: 'require("crypto-js"); CryptoJS.PBKDF2("Secret Passphrase", salt, {keySize: 512 / 32, iterations: 100});',
    //   errors: [
    //     { message: "Key should not be fixed", type: "CallExpression" },
    //     { message: "Less than 1000 iterations", type: "CallExpression" }
    //   ],
    // },
    // {
    //   code: 'require("crypto-js/aes"); CryptoJS.DES.encrypt("Message", "Secret Passphrase");',
    //   errors: [
    //     { message: "Key should not be fixed", type: "CallExpression" },
    //     { message: "DES is not secure", type: "CallExpression" },
    //   ],
    // },
    // {
    //   code: 'require("crypto-js/aes"); CryptoJS.DES.decrypt("Message", "Secret Passphrase");',
    //   errors: [
    //     { message: "Key should not be fixed", type: "CallExpression" },
    //     { message: "DES is not secure", type: "CallExpression" },
    //   ],
    // },
    // {
    //   code: 'require("crypto-js/aes"); CryptoJS.AES.decrypt("Message", "Secret Passphrase");',
    //   errors: [
    //     { message: "Key should not be fixed", type: "CallExpression" },
    //   ],
    // },
    // {
    //   code: 'require("crypto-js/aes"); CryptoJS.AES.encrypt("Message", "Secret Passphrase");',
    //   errors: [
    //     { message: "Key should not be fixed", type: "CallExpression" },
    //   ],
    // },
    // {
    //   code: 'require("crypto-js/aes"); CryptoJS.Rabbit.encrypt("Message", "Secret Passphrase");',
    //   errors: [
    //     { message: "Key should not be fixed", type: "CallExpression" },
    //   ],
    // },
    // {
    //   code: 'require("crypto-js/aes"); CryptoJS.RC4.encrypt("Message", "Secret Passphrase");',
    //   errors: [
    //     { message: "Key should not be fixed", type: "CallExpression" },
    //     { message: "RC4 is not secure", type: "CallExpression" },
    //   ],
    // },
    // {
    //   code: 'require("crypto-js/aes"); RC4Drop.encrypt("Message", "Secret Passphrase");',
    //   errors: [
    //     { message: "Key should not be fixed", type: "CallExpression" },
    //   ],
    // },
    {
      code: 'require("crypto-js/aes"); CryptoJS.AES.encrypt("Message", key, {mode: CryptoJS.mode.ECB});',
      errors: [
        { message: "ECB is not secure", type: "CallExpression" },
      ],
    },
  ],
});
