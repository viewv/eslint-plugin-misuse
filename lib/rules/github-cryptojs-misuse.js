/**
 * @fileoverview Detect Github CryptoJS crypto misuse
 * @author viewv
 */
"use strict";

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

/** @type {import('eslint').Rule.RuleModule} */
module.exports = {
  meta: {
    type: null, // `problem`, `suggestion`, or `layout`
    docs: {
      description: "Detect Github CryptoJS crypto misuse",
      recommended: false,
      url: null, // URL to the documentation page for this rule
    },
    fixable: null, // Or `code` or `whitespace`
    schema: [], // Add a schema if the rule has options
    messages: {
      SHA1: "SHA1 is not secure",
      MD5: "MD5 is not secure",
      RC4: "RC4 is not secure",
      RC2: "RC2 is not secure",
      ECB: "ECB is not secure",
      DES: "DES is not secure",
      LESS_ITER: "Less than 1000 iterations",
      FIX_SALT: "Salt should be random",
      FIX_IV: "IV should be random",
      FIX_KEY: "Key should not be fixed",
      WEAK_PASSWORD: "Weak password",
      DEPRECATED: "Deprecated API",
      TEST: "Test",
    },
  },

  create(context) {
    // variables should be defined here

    var identifierMap = new Array();
    var litealArray = new Array();
    var litealArrayLength = 0;

    const ITERMINIMUM = 1000;

    var usedFlag = false;

    //const Aes = goog.require('goog.crypt.Aes'); 
    //那么 Aes 是一个 module
    //module 同时也是一个 operator·
    // var moduleMap = new Array();

    //const aes = new Aes(keyArray);
    //那么 aes 是一个 operator
    var operatorMap = new Array();

    const methodDict = {
      'PBKDF2': {
        name: "PBKDF2",
        salt: 1,
        option: 2,
        args: 3,
      },
      createEncryptor: {
        name: "createEncryptor",
        option: 1,
        args: 2,
      },
      createDecryptor: {
        name: "createDecryptor",
        option: 1,
        args: 2,
      },
    };

    const unsafeAlgorithm = new Set([
      'MD5',
      'SHA1',
      'HmacSHA1',
      'RC4',
    ]);

    //----------------------------------------------------------------------
    // Helpers
    //----------------------------------------------------------------------

    // any helper functions should go here or else delete this section

    function calBinary(node) {
      var left = node.left;
      var right = node.right;
      var leftValue = 0;
      var rightValue = 0;
      if (left.type === "Literal") {
        leftValue = left.value;
      } else if (left.type === "Identifier" && identifierMap.hasOwnProperty(left.name)) {
        leftValue = litealArray[identifierMap[left.name]];
        if (!leftValue) {
          return null;
        }
      } else {
        return null;
      }
      if (right.type === "Literal") {
        rightValue = right.value;
      } else if (right.type === "Identifier" && identifierMap.hasOwnProperty(right.name)) {
        rightValue = litealArray[identifierMap[right.name]];
        if (!rightValue) {
          return null;
        }
      } else {
        return null;
      }
      var result = null;
      switch (node.operator) {
        case "+":
          result = leftValue + rightValue;
          break;
        case "-":
          result = leftValue - rightValue;
          break;
        case "*":
          result = leftValue * rightValue;
          break;
        case "/":
          result = leftValue / rightValue;
          break;
        case "%":
          result = leftValue % rightValue;
          break;
        case "**":
          result = leftValue ** rightValue;
          break;
        case "<<":
          result = leftValue << rightValue;
          break;
        case ">>":
          result = leftValue >> rightValue;
          break;
        case ">>>":
          result = leftValue >>> rightValue;
          break;
        case "|":
          result = leftValue | rightValue;
          break;
        case "^":
          result = leftValue ^ rightValue;
          break;
        case "&":
          result = leftValue & rightValue;
          break;
        default:
          break;
      }
      return result;
    }

    function calArray(node) {
      var elements = node.elements;
      var array = new Array();
      var flag = true;
      for (var i = 0; i < elements.length; i++) {
        if (elements[i].type === "Literal") {
          array.push(elements[i].value);
        } else if (elements[i].type === "Identifier" && identifierMap.hasOwnProperty(elements[i].name)) {
          var index = identifierMap[elements[i].name];
          if (index !== null) {
            array.push(litealArray[index]);
          } else {
            flag = false;
            break;
          }
        } else if (elements[i].type === "BinaryExpression") {
          var result = calBinary(elements[i]);
          if (result !== null) {
            array.push(result);
          } else {
            flag = false;
            break;
          }
        } else {
          flag = false;
          break;
        }
      }
      if (flag) {
        // litealArrayLength = litealArray.push(array);
        // identifierMap[name] = litealArrayLength - 1;
        return array;
      } else {
        return null;
      }
    }

    function calObject(node) {
      var properties = node.properties;
      var object = {};
      for (var i = 0; i < properties.length; i++) {
        if (properties[i].key.type === "Identifier" && properties[i].value.type === "Literal") {
          object[properties[i].key.name] = properties[i].value.value;
        } else if (properties[i].key.type === "Identifier" && properties[i].value.type === "Identifier") {
          if (identifierMap.hasOwnProperty(properties[i].value.name)) {
            var index = identifierMap[properties[i].value.name];
            if (index !== null) {
              object[properties[i].key.name] = litealArray[index];
            }
          }
        } else if (properties[i].key.type === "Identifier" && properties[i].value.type === "BinaryExpression") {
          var binary = properties[i].value;
          var result = calBinary(binary);
          if (result) {
            object[properties[i].key.name] = result;
          }
        } else if (properties[i].key.type === "Identifier" && properties[i].value.type === "ArrayExpression") {
          var array = calArray(properties[i].value);
          if (array) {
            object[properties[i].key.name] = array;
          }
        } else if (properties[i].key.type === "Identifier" && properties[i].value.type === "ObjectExpression") {
          var object = calObject(properties[i].value);
          if (object) {
            object[properties[i].key.name] = object;
          }
        } else if (properties[i].key.type === "Identifier" && properties[i].value.type === "MemberExpression") {
          var member = properties[i].value;
          if (identifierMap.hasOwnProperty(member.object.name)) {
            var target_object = litealArray[identifierMap[member.object.name]];
            var target_key = member.property.name;
            if (target_object.hasOwnProperty(target_key)) {
              object[properties[i].key.name] = target_object[target_key];
            }
          }
        }
      }
      return object;
    }

    //----------------------------------------------------------------------
    // Public
    //----------------------------------------------------------------------

    return {
      // visitor functions for different types of nodes
      AssignmentExpression: function (node) {
        //也许可以增强提供运算
        if (node.left.type === "Identifier" && node.right.type === "Literal") {
          litealArrayLength = litealArray.push(node.right.value);
          identifierMap[node.left.name] = litealArrayLength - 1;
        } else if (node.left.type === "Identifier" && node.right.type === "ArrayExpression") {
          var elements = node.right.elements;
          var array = new Array();
          var flag = true;
          for (var i = 0; i < elements.length; i++) {
            if (elements[i].type === "Literal") {
              array.push(elements[i].value);
            } else if (elements[i].type === "Identifier" && identifierMap.hasOwnProperty(elements[i].name)) {
              var index = identifierMap[elements[i].name];
              if (index !== null) {
                array.push(litealArray[index]);
              } else {
                flag = false;
                break;
              }
            } else if (elements[i].type === "BinaryExpression") {
              var result = calBinary(elements[i]);
              if (result !== null) {
                array.push(result);
              } else {
                flag = false;
                break;
              }
            } else {
              flag = false;
              break;
            }
          }
          if (flag) {
            litealArrayLength = litealArray.push(array);
            identifierMap[node.left.name] = litealArrayLength - 1;
          }
        } else if (node.left.type === "Identifier" && node.right.type === "Identifier") {
          if (identifierMap.hasOwnProperty(node.right.name)) {
            var index = identifierMap[node.right.name];
            identifierMap[node.left.name] = index;
          } else if (operatorMap.hasOwnProperty(node.right.name)) {
            operatorMap[node.left.name] = operatorMap[node.right.name];
          } else {
            identifierMap[node.left.name] = null;
          }
        } else if (node.left.type === "Identifier" && node.right.type === "BinaryExpression") {
          var binary = node.right;
          var result = calBinary(binary);
          if (result) {
            litealArrayLength = litealArray.push(result);
            identifierMap[node.left.name] = litealArrayLength - 1;
          }
        } else if (node.left.type === "Identifier" && node.right.type === "ObjectExpression") {
          var object = calObject(node.right);
          if (object) {
            litealArrayLength = litealArray.push(object);
            identifierMap[node.left.name] = litealArrayLength - 1;
          }
        } else if (node.left.type === "Identifier" && node.right.type === "MemberExpression") {
          addOperatorWithMemberNode(node.right, node.left.name);
        }
      },
      VariableDeclarator: function (node) {
        if (node.init.type === "Literal") {
          litealArrayLength = litealArray.push(node.init.value);
          identifierMap[node.id.name] = litealArrayLength - 1;
        } else if (node.init.type === "ArrayExpression") {
          var elements = node.init.elements;
          var array = new Array();
          var flag = true;
          for (var i = 0; i < elements.length; i++) {
            if (elements[i].type === "Literal") {
              array.push(elements[i].value);
            } else if (elements[i].type === "Identifier" && identifierMap.hasOwnProperty(elements[i].name)) {
              var index = identifierMap[elements[i].name];
              if (index !== null) {
                array.push(litealArray[index]);
              } else {
                flag = false;
                break;
              }
            } else if (elements[i].type === "BinaryExpression") {
              var result = calBinary(elements[i]);
              if (result !== null) {
                array.push(result);
              } else {
                flag = false;
                break;
              }
            } else {
              flag = false;
              break;
            }
          }
          if (flag) {
            litealArrayLength = litealArray.push(array);
            identifierMap[node.id.name] = litealArrayLength - 1;
          }
        } else if (node.init.type === "Identifier") {
          if (identifierMap.hasOwnProperty(node.init.name)) {
            var index = identifierMap[node.init.name];
            identifierMap[node.id.name] = index;
          } else if (operatorMap.hasOwnProperty(node.init.name)) {
            operatorMap[node.id.name] = operatorMap[node.init.name];
          } else {
            identifierMap[node.id.name] = null;
          }
        } else if (node.init.type === "BinaryExpression") {
          var binary = node.init;
          var result = calBinary(binary);
          if (result) {
            litealArrayLength = litealArray.push(result);
            identifierMap[node.id.name] = litealArrayLength - 1;
          }
        } else if (node.init.type === "ObjectExpression") {
          var object = calObject(node.init);
          if (object) {
            litealArrayLength = litealArray.push(object);
            identifierMap[node.id.name] = litealArrayLength - 1;
          }
        } else if (node.init.type === "MemberExpression") {
          var member = node.init;
          addOperatorWithMemberNode(member, node.id.name);
        }
      },
      CallExpression: function (node) {
        var callee = node.callee;
        var args = node.arguments;
        if (callee.type === "Identifier") {

        } else if (callee.type === "MemberExpression") {
          
        }
      },
      Literal: function (node) {
        if (node.value.startsWith('crypto-js')) {
          usedFlag = true;
        }
      },
    };
  },
};
