/**
 * @fileoverview Detect crypto misuse of the web crypto misuse API in code
 * @author viewv
 */
"use strict";

//------------------------------------------------------------------------------
// Requirements
//------------------------------------------------------------------------------

const rule = require("../../../lib/rules/webcrypto-misuse"),
  RuleTester = require("eslint").RuleTester;


//------------------------------------------------------------------------------
// Tests
//------------------------------------------------------------------------------

const ruleTester = new RuleTester();
ruleTester.run("webcrypto-misuse", rule, {
  valid: [
    // give me some code that won't trigger a warning
  ],

  invalid: [
    {
      code: "var hash = crypto.subtle.digest('SHA-1', data)",
      errors: [
        { message: "SHA1 is not secure", type: "CallExpression" },
      ],
    },
    {
      code: "x = 'SHA-1'; var hash = crypto.subtle.digest(x, data)",
      errors: [
        { message: "SHA1 is not secure", type: "CallExpression" },
      ],
    },
    {
      code: "x = 'SHA-1'; var hash = self.window.crypto.subtle.digest(x, data)",
      errors: [
        { message: "SHA1 is not secure", type: "CallExpression" },
      ],
    },
    {
      code: "x = 'SHA-1'; var hash = self.crypto.subtle.digest(x, data)",
      errors: [
        { message: "SHA1 is not secure", type: "CallExpression" },
      ],
    },
    {
      code: "x = 'SHA-1'; dig = crypto.subtle; var hash = dig.digest(x, data)",
      errors: [
        { message: "SHA1 is not secure", type: "CallExpression" },
      ],
    },
    {
      code: 'key = window.crypto.subtle.generateKey({name: "HMAC", hash: {name: "SHA-1"}},true,["sign", "verify"]);',
      errors: [
        { message: "SHA1 is not secure", type: "CallExpression" },
      ],
    },
  ],
});
