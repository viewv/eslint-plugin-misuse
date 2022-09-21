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
      MD4: "MD4 is not secure",
      MD5: "MD5 is not secure",
      RC2: "RC2 is not secure",
      RC4: "RC4 is not secure",  
      ECB: "ECB is not secure",
      CBC: "CBC is not secure",
      DES: "DES is not secure",
      SHORT_RSA_KEY : "Key length is too short, suggest to use 2048 bits or more",
      LESS_ITER: "Less than 1000 iterations",
      FIX_SALT: "Salt should be random",
      FIX_IV: "IV should be random",
      FIX_KEY: "Key should not be fixed",
      WEAK_PASSWORD: "Weak password",
      DEPRECATED: "Deprecated API",
      RSA_NO_PADDING: "RSA should not use no padding",
      RSA_PKCS1_PADDING: "RSA should not use PKCS1-v1_5 padding",
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

    // const methodDict = {
    //   'PBKDF2': {
    //     name: "PBKDF2",
    //     salt: 1,
    //     option: 2,
    //     args: 3,
    //   },
    //   createEncryptor: {
    //     name: "createEncryptor",
    //     option: 1,
    //     args: 2,
    //   },
    //   createDecryptor: {
    //     name: "createDecryptor",
    //     option: 1,
    //     args: 2,
    //   },
    // };

    const cipherSet = new Set([
      "AES",
      "DES",
      "TripleDES",
      "RC4",
      "RC4Drop",
      "Rabbit",
    ]);

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

    function staticTester(parameter){
      if (parameter.type === "Literal"){
        return true;
      } else if (parameter.type === "Identifier" && identifierMap.hasOwnProperty(parameter.name)){
        var value = litealArray[identifierMap[parameter.name]];
        if (value){
          return true;
        }
      } else if (parameter.type === "MemberExpression"){
        if (parameter.object.type === "Identifier" && identifierMap.hasOwnProperty(parameter.object.name)){
          var target_key = parameter.object.name;
          var target_value = parameter.property.name;
          var target_object = litealArray[identifierMap[target_key]];
          if (target_object) {
            if (target_object.hasOwnProperty(target_value)) {
              var keyValue = target_object[target_value];
              if (keyValue) {
                return true;
              }
            }
          }
        }
      } else if (parameter.type === "BinaryExpression"){
        var target = calBinary(parameter);
        if (target){
          return true;
        }
      }
      return false;
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
        var method = null;
        if (usedFlag) {
          //TODO 增加 Progressive HMAC Hashing 模式的检测
          if (callee.type === "Identifier") {
            method = callee.name;
          } else if (callee.type === "MemberExpression") {
            method = callee.property.name;
          }
          if (method === "MD5" || method === "HmacMD5"){
            context.report({
              node: node,
              messageId: "MD5",
            });
          }
          if (method === "SHA1" || method === "HmacSHA1"){
            context.report({
              node: node,
              messageId: "SHA1",
            });
          }
          if (method === "HmacMD5" || method === "HmacSHA1"){
            if (args.length >= 2){
              var key = args[1];
              if (staticTester(key)){
                context.report({
                  node: node,
                  messageId: "FIX_KEY",
                });
              }
            }
          }
          if (method === "PBKDF2"){
            if (args.length >= 3){
              var key = args[0];
              var salt = args[1];
              var options = args[2];
              if (staticTester(key)){
                context.report({
                  node: node,
                  messageId: "FIX_KEY",
                });
              }
              if (staticTester(salt)){
                context.report({
                  node: node,
                  messageId: "FIX_SALT",
                });
              }
              if (options.type === "ObjectExpression"){
                var target_options = calObject(options);
                if (target_options && target_options.hasOwnProperty('iterations')){
                  var iter = target_options['iterations'];
                  if (iter && Number.isInteger(iter) && iter < ITERMINIMUM){
                    context.report({
                      node: node,
                      messageId: "LESS_ITER",
                    });
                  }
                }
              }
            }
          }
          if (method === "encrypt" || method === "decrypt"){
            var algorithm = null;
            if (callee.object.type === "Identifier"){
              algorithm = callee.object.name;
            } else if (callee.object.type === "MemberExpression"){
              var object = callee.object;
              if (object.property.type === "Identifier"){
                algorithm = object.property.name;
              }
            }
            if (algorithm && cipherSet.has(algorithm)){
              if (args.length >= 2){
                var key = args[1];
                if (staticTester(key)){
                  context.report({
                    node: node,
                    messageId: "FIX_KEY",
                  });
                }
                if (algorithm === "DES"){
                  context.report({
                    node: node,
                    messageId: "DES",
                  });
                }
                if (algorithm === "RC4"){
                  context.report({
                    node: node,
                    messageId: "RC4",
                  });
                }
              }
              if (args.length >=3){
                var options = args[2];
                if (options.type === "ObjectExpression"){
                  var properties = options.properties;
                  for (var i = 0; i < properties.length; i++){
                    var property = properties[i];
                    if (property.key.type === "Identifier" && property.key.name === "mode"){
                      var mode = property.value;
                      if (mode.type === "MemberExpression" && mode.property.type === "Identifier"){
                        var modeName = mode.property.name;
                        if (modeName === "ECB"){
                          context.report({
                            node: node,
                            messageId: "ECB",
                          });
                        } else if (modeName === "CBC"){
                          context.report({
                            node: node,
                            messageId: "CBC",
                          });
                        } 
                      }
                    }
                  }
                  var target_options = calObject(options);
                  if (target_options && target_options.hasOwnProperty('iv')){
                    var iv = target_options['iv'];
                    if (iv){
                      context.report({
                        node: node,
                        messageId: "FIX_IV",
                      });
                    }
                  }
                }
              }
            }
          }
          if (method === "createEncryptor" || method === "createDecryptor"){
            var algorithm = null;
            if (callee.object.type === "Identifier"){
              algorithm = callee.object.name;
            } else if (callee.object.type === "MemberExpression"){
              var object = callee.object;
              if (object.property.type === "Identifier"){
                algorithm = object.property.name;
              }
            }
            if (algorithm && cipherSet.has(algorithm)){
              if (args.length >= 2){
                var key = args[0];
                var iv = args[1];
                if (algorithm === "DES"){
                  context.report({
                    node: node,
                    messageId: "DES",
                  });
                }
                if (algorithm === "RC4"){
                  context.report({
                    node: node,
                    messageId: "RC4",
                  });
                }
                if (staticTester(key)){
                  context.report({
                    node: node,
                    messageId: "FIX_KEY",
                  });
                }
                if (iv.type === "ObjectExpression"){
                  var iv_object = calObject(iv);
                  if (iv_object.hasOwnProperty('iv')){
                    var iv = target_options['iv'];
                    if (iv){
                      context.report({
                        node: node,
                        messageId: "FIX_IV",
                      });
                    }
                  }
                }
              }
            }
          }
        }
      },
      Literal: function (node) {
        var value = node.value;
        if (usedFlag != true && typeof(value) == 'string' && value.startsWith('crypto-js')) {
          usedFlag = true;
        }
      },
    };
  },
};
