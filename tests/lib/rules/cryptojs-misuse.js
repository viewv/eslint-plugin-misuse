/**
 * @fileoverview Detect crypto misuse in crypto-js
 * @author viewv
 */
"use strict";

//------------------------------------------------------------------------------
// Requirements
//------------------------------------------------------------------------------

const rule = require("../../../lib/rules/cryptojs-misuse"),
  RuleTester = require("eslint").RuleTester;


//------------------------------------------------------------------------------
// Tests
//------------------------------------------------------------------------------

const ruleTester = new RuleTester();
ruleTester.run("cryptojs-misuse", rule, {
  valid: [
    // give me some code that won't trigger a warning
  ],

  invalid: [
    {
      code: "var Certificate = require('node:crypto'); crypto.createCipher('aes-256-ecb',0,0);",
      errors: [
        { message: "Deprecated API", type: "CallExpression" },
        { message: "ECB is not secure", type: "CallExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
    {
      code: "require('node:crypto'); createCipher('aes-256-ecb',0,0);",
      errors: [
        { message: "Deprecated API", type: "CallExpression" },
        { message: "ECB is not secure", type: "CallExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
    {
      code: "require('node:crypto'); pbkdf2('secret', 'salt', 100, 64, 'sha512');",
      errors: [
        { message: "Salt should be random", type: "CallExpression" },
        { message: "Less than 1000 iterations", type: "CallExpression" },
      ],
    },
    {
      code: "require('crypto'); generateKeyPairSync('rsa', {modulusLength: 1024,});",
      errors: [
        { message: "Key length is too short, suggest to use 2048 bits or more", type: "CallExpression" },
      ],
    },
    {
      code: "require('crypto'); k = 1024; generateKeyPairSync('rsa', {modulusLength: k,});",
      errors: [
        { message: "Key length is too short, suggest to use 2048 bits or more", type: "CallExpression" },
      ],
    },
  ],
});
