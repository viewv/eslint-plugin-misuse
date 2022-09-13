/**
 * @fileoverview crypto misuse
 * @author viewv
 */
"use strict";

//------------------------------------------------------------------------------
// Requirements
//------------------------------------------------------------------------------

const rule = require("../../../lib/rules/misuse"),
  RuleTester = require("eslint").RuleTester;


//------------------------------------------------------------------------------
// Tests
//------------------------------------------------------------------------------

const ruleTester = new RuleTester();
ruleTester.run("misuse", rule, {
  valid: [
    {
      code: "goog.require('goog.crypt.pbkdf2'); goog.crypt.pbkdf2.deriveKeySha1(1, s, 2000, 160);",
      errors: [{ message: "Less than 1000 iterations", type: "CallExpression" }],
    },
    {
      code: "PBK = goog.require('goog.crypt.pbkdf2'); pbk = new PBK(); key = pbk.deriveKeySha1(1, s, 1200, 160);",
      errors: [{ message: "Less than 1000 iterations", type: "CallExpression" }],
    },
    {
      code: "PBK = goog.require('goog.crypt.pbkdf2'); pbk = new PBK(); t = 1200, key = pbk.deriveKeySha1(1, s, t, 160);",
      errors: [{ message: "Less than 1000 iterations", type: "CallExpression" }],
    },
    {
      code: "PBK = goog.require('goog.crypt.pbkdf2'); pbk = new PBK(); t = 1200, k = t; key = pbk.deriveKeySha1(1, s, k, 160);",
      errors: [{ message: "Less than 1000 iterations", type: "CallExpression" }],
    },
    {
      code: "pbkdf2 = goog.require('goog.crypt.pbkdf2'); t = Math.random(); m = t; pbkdf2.deriveKeySha1(testPassword, m, 1200, 160);",
      errors: [{ message: "Salt should be random", type: "CallExpression" }],
    },
  ],
  invalid: [
    {
      code: 'goog.require("goog.crypt.Sha1"); goog.crypt.Sha1.base(this, "constructor");',
      errors: [{ message: "SHA1 is not secure", type: "MemberExpression" }],
    },
    {
      code: 'goog.provide("goog.crypt.Aes"); goog.crypt.Aes.assertKeyArray_(key);',
      errors: [{ message: "ECB is not secure", type: "MemberExpression" }],
    },
    {
      code: "Aes = goog.require('goog.crypt.Aes'); aes = new Aes(keyArray); outputArr = aes.encrypt(inputArr);",
      errors: [{ message: "ECB is not secure", type: "MemberExpression" }],
    },
    {
      code: "goog.require('goog.crypt.pbkdf2'); goog.crypt.pbkdf2.deriveKeySha1(1, salt, 120, 160);",
      errors: [{ message: "Less than 1000 iterations", type: "CallExpression" }],
    },
    {
      code: "PBK = goog.require('goog.crypt.pbkdf2'); pbk = new PBK(); key = pbk.deriveKeySha1(1, salt, 120, 160);",
      errors: [{ message: "Less than 1000 iterations", type: "CallExpression" }],
    },
    {
      code: "PBK = goog.require('goog.crypt.pbkdf2'); pbk = new PBK(); t = 120, key = pbk.deriveKeySha1(1, salt, t, 160);",
      errors: [{ message: "Less than 1000 iterations", type: "CallExpression" }],
    },
    {
      code: "PBK = goog.require('goog.crypt.pbkdf2'); pbk = new PBK(); t = 120, k = t; key = pbk.deriveKeySha1(1, salt, k, 160);",
      errors: [{ message: "Less than 1000 iterations", type: "CallExpression" }],
    },
    {
      code: "pbkdf2 = goog.require('goog.crypt.pbkdf2'); pbkdf2.deriveKeySha1(testPassword, testSalt, 1, 160);",
      errors: [{ message: "Less than 1000 iterations", type: "CallExpression" }],
    },
    {
      code: "Arc4 = goog.require('goog.crypt.Arc4'); arc4 = new Arc4(); arc4.crypt(byteArray);",
      errors: [{ message: "RC4 is not secure", type: "MemberExpression" }],
    },
    {
      code: "pbkdf2 = goog.require('goog.crypt.pbkdf2'); pbkdf2.deriveKeySha1(testPassword, 2, 1200, 160);",
      errors: [{ message: "Salt should be random", type: "CallExpression" }],
    },
    {
      code: "pbkdf2 = goog.require('goog.crypt.pbkdf2'); t = 30; m = t; pbkdf2.deriveKeySha1(testPassword, m, 1200, 160);",
      errors: [{ message: "Salt should be random", type: "CallExpression" }],
    },
    {
      code: "Aes = goog.require('goog.crypt.Aes'); aes = new Aes(1); outputArr = aes.encrypt(inputArr);",
      errors: [
        { message: "Key should not be fixed", type: "NewExpression" },
        { message: "ECB is not secure", type: "MemberExpression" }
      ],
    },
    {
      code: "Aes = goog.require('goog.crypt.Aes'); t = 10; m = t; aes = new Aes(m); outputArr = aes.encrypt(inputArr);",
      errors: [
        { message: "Key should not be fixed", type: "NewExpression" },
        { message: "ECB is not secure", type: "MemberExpression" }
      ],
    },
    {
      code: "Arc4 = goog.require('goog.crypt.Arc4'); arc4 = new Arc4(); arc4.setKey(1);",
      errors: [
        { message: "RC4 is not secure", type: "MemberExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
    {
      code: "Ctr = goog.require('goog.crypt.Ctr'); ctr = new Ctr(); ctr.decrypt(1, 1);",
      errors: [
        { message: "IV should be random", type: "CallExpression" },
      ],
    },
    {
      code: "Ctr = goog.require('goog.crypt.Ctr'); ctr = new Ctr(); t = 10; m = t; ctr.encrypt(1, m);",
      errors: [
        { message: "IV should be random", type: "CallExpression" },
      ],
    },
    {
      code: "Cbc = goog.require('goog.crypt.Cbc'); cbc = new Cbc(); cbc.decrypt(1, 1);",
      errors: [
        { message: "IV should be random", type: "CallExpression" },
      ],
    },
    {
      code: "Cbc = goog.require('goog.crypt.Cbc'); cbc = new Cbc(); t = 10; m = t; cbc.encrypt(1, m);",
      errors: [
        { message: "IV should be random", type: "CallExpression" },
      ],
    },
    {
      code: "Arc4 = goog.require('goog.crypt.Arc4'); arc4 = new Arc4(); key = [0x25, 0x26, 0x27, 0x28]; arc4.setKey(key);",
      errors: [
        { message: "RC4 is not secure", type: "MemberExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
    {
      code: "Arc4 = goog.require('goog.crypt.Arc4'); arc4 = new Arc4(); key = [0x25, 0x26, 0x27, 0x28]; m = key; arc4.setKey(m);",
      errors: [
        { message: "RC4 is not secure", type: "MemberExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
    {
      code: "Arc4 = goog.require('goog.crypt.Arc4'); arc4 = new Arc4(); key = 2; m = key * 3; arc4.setKey(m);",
      errors: [
        { message: "RC4 is not secure", type: "MemberExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
    {
      code: "Arc4 = goog.require('goog.crypt.Arc4'); arc4 = new Arc4(); key = 'key'; m = key + '123'; arc4.setKey(m);",
      errors: [
        { message: "RC4 is not secure", type: "MemberExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
    {
      code: "Arc4 = goog.require('goog.crypt.Arc4'); arc4 = new Arc4(); t = 0x28; key = [0x25, 0x26, 0x27, t]; m = key; arc4.setKey(m);",
      errors: [
        { message: "RC4 is not secure", type: "MemberExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
    {
      code: "Arc4 = goog.require('goog.crypt.Arc4'); arc4 = new Arc4(); t = 0x28; key = [0x25, 0x26, 0x27, 2*t]; m = key; arc4.setKey(m);",
      errors: [
        { message: "RC4 is not secure", type: "MemberExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
    {
      code: "Arc4 = goog.require('goog.crypt.Arc4'); arc4 = new Arc4(); var t = 0x28; var key = [0x25, 0x26, 0x27, 2*t]; var m = key; arc4.setKey(m);",
      errors: [
        { message: "RC4 is not secure", type: "MemberExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
    {
      code: "Arc4 = goog.require('goog.crypt.Arc4'); arc4 = new Arc4(); var t = 0x28; var key = [0x25, 0x26, 0x27, 2*t]; var m = {k: key}; arc4.setKey(m.k);",
      errors: [
        { message: "RC4 is not secure", type: "MemberExpression" },
        { message: "Key should not be fixed", type: "CallExpression" },
      ],
    },
  ],
});
