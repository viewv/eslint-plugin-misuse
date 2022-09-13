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
    //   code: "",
    //   errors: [{ message: "Fill me in.", type: "Me too" }],
    // },
  ],
});
