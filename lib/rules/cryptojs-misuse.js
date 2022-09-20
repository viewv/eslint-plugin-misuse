/**
 * @fileoverview Detect crypto misuse in crypto-js
 * @author viewv
 */
"use strict";

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

/** @type {import('eslint').Rule.RuleModule} */
module.exports = {
  parserOptions: {
    ecmaVersion: 7
  },
  env: {
    node: true,
    es6: true,
  },
  meta: {
    type: null, // `problem`, `suggestion`, or `layout`
    docs: {
      description: "Detect crypto misuse in crypto-js",
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
    }
  },

  create(context) {
    // variables should be defined here

    var identifierMap = new Array();
    var litealArray = new Array();
    var litealArrayLength = 0;

    const ITERMINIMUM = 1000;

    //const Aes = goog.require('goog.crypt.Aes'); 
    //那么 Aes 是一个 module
    //module 同时也是一个 operator·
    // var moduleMap = new Array();

    //const aes = new Aes(keyArray);
    //那么 aes 是一个 operator
    var operatorMap = new Array();

    const methodDict = {
      createCipher: {
        name: "createCipher",
        deprecated: true,
        algorithm: 0,
        key: 1,
        args: 2,
      },
      createCipheriv: {
        name: "createCipheriv",
        deprecated: false,
        algorithm: 0,
        key: 1,
        iv: 2,
        args: 3,
      },
      createDecipher: {
        name: "createDecipher",
        deprecated: true,
        algorithm: 0,
        key: 1,
        args: 2,
      },
      createDecipheriv: {
        name: "createDecipheriv",
        deprecated: false,
        algorithm: 0,
        key: 1,
        iv: 2,
        args: 3,
      },
      createHash: {
        name: "createHash",
        deprecated: false,
        algorithm: 0,
        args: 1,
      },
      createHmac: {
        name: "createHmac",
        deprecated: false,
        algorithm: 0,
        key: 1,
        args: 2,
      },
      createSign: {
        name: "createSign",
        deprecated: false,
        algorithm: 0,
        args: 1,
      },
      createVerify: {
        name: "createVerify",
        deprecated: false,
        algorithm: 0,
        args: 1,
      },
      hkdf: {
        name: "hkdf",
        deprecated: false,
        algorithm: 0,
        salt: 2,
        args: 4,
      },
      hkdfSync: {
        name: "hkdfSync",
        deprecated: false,
        algorithm: 0,
        salt: 2,
        args: 4,
      },
      pbkdf2: {
        name: "pbkdf2",
        deprecated: false,
        password: 0,
        salt: 1,
        iterations: 2,
        algorithm: 4,
        args: 5,
      },
      pbkdf2Sync: {
        name: "pbkdf2Sync",
        deprecated: false,
        password: 0,
        salt: 1,
        iterations: 2,
        algorithm: 4,
        args: 5,
      },
      scrypt: {
        name: "scrypt",
        deprecated: false,
        password: 0,
        salt: 1,
        args: 3,
      },
      scryptSync: {
        name: "scryptSync",
        deprecated: false,
        password: 0,
        salt: 1,
        args: 3,
      },
      sign: {
        name: "sign",
        deprecated: false,
        algorithm: 0,
        key: 2,
        args: 3,
      },
      verify: {
        name: "verify",
        deprecated: false,
        algorithm: 0,
        key: 2,
        args: 3,
      },
    };

    const unsafeAlgorithmMD4Set = new Set([
      'RSA-MD4',
      'md4',
      'MD4',
      'md4WithRSAEncryption',
    ]);

    const unsafeAlgorithmMD5Set = new Set([
      'md5',
      'MD5',
      'RSA-MD5',
      'ssl3-md5',
      'md5WithRSAEncryption',
    ]);

    const unsafeAlgorithmSHA1Set = new Set([
      'DSA-SHA',
      'DSA-SHA1',
      'DSA-SHA1-old',
      'RSA-SHA',
      'RSA-SHA1',
      'RSA-SHA1-2',
      'dsaWithSHA',
      'dsaWithSHA1',
      'sha',
      'sha1',
      'SHA1',
      'sha1WithRSAEncryption',
      'ssl3-sha1',
    ]);

    const unsafeAlgorithmRC2Set = new Set([
      'rc2',
      'rc2-40-cbc',
      'rc2-64-cbc',
      'rc2-cbc',
      'rc2-cfb',
      'rc2-ecb',
      'rc2-ofb',
      'RC2',
    ]);

    const unsafeAlgorithmRC4Set = new Set([
      'rc4',
      'rc4-40',
      'rc4-hmac-md5',
      'RC4',
    ]);

    const unsafeAlgorithmECBSet = new Set([
      'aes-128-ecb',
      'aes-256-ecb',
      'AES-128-ECB',
      'AES-192-ECB',
      'AES-256-ECB',
      'ARIA-128-ECB',
      'ARIA-192-ECB',
      'ARIA-256-ECB',
      'BF-ECB',
      'CAMELLIA-128-ECB',
      'CAMELLIA-192-ECB',
      'CAMELLIA-256-ECB',
      'CAST5-ECB',
      'DES-ECB',
      'IDEA-ECB',
      'RC2-ECB',
      'SEED-ECB',
      'SM4-ECB',
    ]);

    const unsafeAlgorithmDESSet = new Set([
      'des',
      'des-cbc',
      'des-cfb',
      'des-cfb1',
      'des-cfb8',
      'des-ecb',
      'des-ede',
      'des-ede-cbc',
      'des-ede-cfb',
      'des-ede-ofb',
      'des-ede3',
      'des-ede3-cbc',
      'des-ede3-cfb',
      'des-ede3-cfb1',
      'des-ede3-cfb8',
      'des-ede3-ofb',
      'des-ofb',
      'DES-CBC',
      'DES-CFB',
      'DES-CFB1',
      'DES-CFB8',
      'DES-ECB',
      'DES-EDE',
      'DES-EDE-CBC',
      'DES-EDE-CFB',
      'des-ede-ecb',
      'DES-EDE-OFB',
      'DES-EDE3',
      'DES-EDE3-CBC',
      'DES-EDE3-CFB',
      'DES-EDE3-CFB1',
      'DES-EDE3-CFB8',
      'des-ede3-ecb',
      'DES-EDE3-OFB',
      'DES-OFB',
    ]);

    const unsafeAlgorithmCBCSet = new Set([
      'AES-128-CBC',
      'AES-128-CBC-HMAC-SHA1',
      'AES-128-CBC-HMAC-SHA256',
      'aes128',
      'aes192',
      'AES-192-CBC',
      'aes256',
      'AES-256-CBC',
      'ARIA-128-CBC',
      'ARIA-256-CBC',
      'aria128',
      'aria192',
      'aria256',
      'bf',
      'BF-CBC',
      'blowfish',
      'CAMELLIA-128-CBC',
      'CAMELLIA-256-CBC',
      'camellia128',
      'camellia192',
      'camellia256',
      'cast',
      'cast-cbc',
      'CAST5-CBC',
      'des',
      'DES-CBC',
      'DES-EDE-CBC',
      'DES-EDE3-CBC',
      'des3',
      'desx',
      'DESX-CBC',
      'idea',
      'IDEA-CBC',
      'rc2',
      'rc2-128',
      'rc2-40',
      'RC2-40-CBC',
      'rc2-64',
      'RC2-64-CBC',
      'RC2-CBC',
      'seed',
      'SEED-CBC',
      'sm4',
      'SM4-CBC',
    ]);

    //In OpenSSL
    const unsafeAlgorithm = new Set([
      ...unsafeAlgorithmRC2Set,
      ...unsafeAlgorithmRC4Set,
      ...unsafeAlgorithmSHA1Set,
      ...unsafeAlgorithmMD5Set,
      ...unsafeAlgorithmMD4Set,
      ...unsafeAlgorithmDESSet,
      ...unsafeAlgorithmECBSet,
      ...unsafeAlgorithmCBCSet,
    ]);

    var usedFlag = false;
    //----------------------------------------------------------------------
    // Helpers
    //----------------------------------------------------------------------
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

    function reportWithNodeAndAlgorithmValue(node, algorithmValue) {
      if (unsafeAlgorithmRC2Set.has(algorithmValue)) {
        context.report({
          node: node,
          messageId: "RC2",
          data: {
            name: algorithmValue
          }
        });
      } else if (unsafeAlgorithmDESSet.has(algorithmValue)) {
        context.report({
          node: node,
          messageId: "DES",
          data: {
            name: algorithmValue
          }
        });
      } else if (unsafeAlgorithmRC4Set.has(algorithmValue)) {
        context.report({
          node: node,
          messageId: "RC4",
          data: {
            name: algorithmValue
          }
        });
      } else if (unsafeAlgorithmMD5Set.has(algorithmValue)) {
        context.report({
          node: node,
          messageId: "MD5",
          data: {
            name: algorithmValue
          }
        });
      } else if (unsafeAlgorithmSHA1Set.has(algorithmValue)) {
        context.report({
          node: node,
          messageId: "SHA1",
          data: {
            name: algorithmValue
          }
        });
      } else if (unsafeAlgorithmMD4Set.has(algorithmValue)) {
        context.report({
          node: node,
          messageId: "MD4",
          data: {
            name: algorithmValue
          }
        });
      } else if (unsafeAlgorithmECBSet.has(algorithmValue)) {
        context.report({
          node: node,
          messageId: "ECB",
          data: {
            name: algorithmValue
          }
        });
      } else if (unsafeAlgorithmCBCSet.has(algorithmValue)) {
        context.report({
          node: node,
          messageId: "CBC",
          data: {
            name: algorithmValue
          }
        });
      }
    }

    //methodData是methodDict中的一个字典数据
    //TODO: 需要检查参数列表是否满足长度要求
    function reportWithCallNodeAndMethodData(node, methodData) {
      if (methodData.deprecated) {
        context.report({
          node: node,
          messageId: "DEPRECATED",
          // message: "The method {{name}} is deprecated, use {{newName}} instead.",
          data: {
            name: methodData.name,
            //newName: node.callee.property.name.replace("createCipher", "createCipheriv")
          }
        });
      }
      if (methodData.hasOwnProperty("algorithm")) {
        var algorithm = node.arguments[methodData.algorithm];
        if (algorithm.type === "Literal") {
          if (unsafeAlgorithm.has(algorithm.value)) {
            reportWithNodeAndAlgorithmValue(node, algorithm.value);
          }
        } else if (algorithm.type === "Identifier" && identifierMap.hasOwnProperty(algorithm.name)) {
          var value = litealArray[identifierMap[algorithm.name]];
          if (value && unsafeAlgorithm.has(value)) {
            reportWithNodeAndAlgorithmValue(node, value);
          }
        } else if (algorithm.type === "MemberExpression" && identifierMap.hasOwnProperty(algorithm.object.name)) {
          var target_object = litealArray[identifierMap[algorithm.object.name]];
          var target_key = algorithm.property.name;
          if (target_object.hasOwnProperty(target_key)) {
            var value = target_object[target_key];
            if (value && unsafeAlgorithm.has(value)) {
              reportWithNodeAndAlgorithmValue(node, value);
            }
          }
        }
      }
      if (methodData.hasOwnProperty("iv")){
        var iv = node.arguments[methodData.iv];
        if (iv.type === "Literal") {
          context.report({
            node: node,
            messageId: "FIX_IV",
          });
        } else if (iv.type === "Identifier" && identifierMap.hasOwnProperty(iv.name)) {
          var value = litealArray[identifierMap[iv.name]];
          if (value) {
            context.report({
              node: node,
              messageId: "FIX_IV",
            });
          }
        } else if (iv.type === "MemberExpression" && identifierMap.hasOwnProperty(iv.object.name)) {
          var target_object = litealArray[identifierMap[iv.object.name]];
          var target_key = iv.property.name;
          if (target_object.hasOwnProperty(target_key)) {
            var targetValue = target_object[target_key];
            if (targetValue) {
              context.report({
                node: node,
                messageId: "FIX_IV",
              });
            }
          }
        }
      }
      if (methodData.hasOwnProperty("salt")){
        var salt = node.arguments[methodData.salt];
        if (salt.type === "Literal") {
          context.report({
            node: node,
            messageId: "FIX_SALT",
          });
        } else if (salt.type === "Identifier" && identifierMap.hasOwnProperty(salt.name)) {
          var value = litealArray[identifierMap[salt.name]];
          if (value) {
            context.report({
              node: node,
              messageId: "FIX_SALT",
            });
          }
        } else if (salt.type === "MemberExpression" && identifierMap.hasOwnProperty(salt.object.name)) {
          var target_object = litealArray[identifierMap[salt.object.name]];
          var target_key = salt.property.name;
          if (target_object.hasOwnProperty(target_key)) {
            var targetValue = target_object[target_key];
            if (targetValue) {
              context.report({
                node: node,
                messageId: "FIX_SALT",
              });
            }
          }
        }
      }
      if (methodData.hasOwnProperty("key")){
        var key = node.arguments[methodData.key];
        if (key.type === "Literal") {
          context.report({
            node: node,
            messageId: "FIX_KEY",
          });
        } else if (key.type === "Identifier" && identifierMap.hasOwnProperty(key.name)) {
          var value = litealArray[identifierMap[key.name]];
          if (value) {
            context.report({
              node: node,
              messageId: "FIX_KEY",
            });
          }
        } else if (key.type === "MemberExpression" && identifierMap.hasOwnProperty(key.object.name)) {
          var target_object = litealArray[identifierMap[key.object.name]];
          var target_key = key.property.name;
          if (target_object.hasOwnProperty(target_key)) {
            var targetValue = target_object[target_key];
            if (targetValue) {
              context.report({
                node: node,
                messageId: "FIX_KEY",
              });
            }
          }
        }
      }
      if (methodData.hasOwnProperty("iterations")){
        var iterations = node.arguments[methodData.iterations];
        var iterValue;
        if (iterations.type === "Literal") {
          iterValue = iterations.value;
          if (Number.isInteger(iterValue) && iterValue < ITERMINIMUM) {
            context.report({
              node: node,
              messageId: "LESS_ITER",
            });
          }
        } else if (iterations.type === "Identifier" && identifierMap.hasOwnProperty(iterations.name)) {
          iterValue = litealArray[identifierMap[iterations.name]];
          if (Number.isInteger(iterValue) && iterValue < ITERMINIMUM) {
            context.report({
              node: node,
              messageId: "LESS_ITER",
            });
          }
        } else if (iterations.type === "MemberExpression" && identifierMap.hasOwnProperty(iterations.object.name)) {
          var target_object = litealArray[identifierMap[iterations.object.name]];
          var target_key = iterations.property.name;
          if (target_object.hasOwnProperty(target_key)) {
            var targetValue = target_object[target_key];
            if (Number.isInteger(targetValue) && targetValue < ITERMINIMUM) {
              context.report({
                node: node,
                messageId: "LESS_ITER",
              });
            }
          }
        }
      }
    }

    // any helper functions should go here or else delete this section

    //----------------------------------------------------------------------
    // Public
    //----------------------------------------------------------------------

    return {
      // visitor functions for different types of nodes
      //需要增加对operator的支持，比如x是一个operator，y=x的情况
      //还需要增加一种情况ImportDeclaration比如
      // const { Certificate } = await import('node:crypto');
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
      Literal: function (node) {
        if (node.value === "node:crypto") {
          usedFlag = true;
        }
        if (node.value === "crypto") {
          usedFlag = true;
        }
      },
      CallExpression: function (node) {
        if (usedFlag) {
          var method;
          if (node.callee.type === "MemberExpression") {
            method = node.callee.property.name;
          } else if (node.callee.type === "Identifier") {
            method = node.callee.name;
          }
          if (methodDict.hasOwnProperty(method)) {
            reportWithCallNodeAndMethodData(node, methodDict[method]);
          }
          // 非常丑陋，但是先这样写着
          if (method === "generateKeyPairSync" || method === 'generateKeyPair'){
            var args = node.arguments;
            if (args.length >= 2) {
              var type = args[0];
              var options = args[1];
              var rsaflag = false;
              if (type.type === "Literal" && (type.value === "rsa" || type.value === "rsa-pss")) {
                rsaflag = true;
              } else if (type.type === "Identifier" && identifierMap.hasOwnProperty(type.name)) {
                var value = litealArray[identifierMap[type.name]];
                if (value === "rsa" || value === "rsa-pss") {
                  rsaflag = true;
                }
              } else if (type.type === "MemberExpression" && identifierMap.hasOwnProperty(type.object.name)) {
                var value = litealArray[identifierMap[type.object.name]];
                if (value === "rsa" || value === "rsa-pss") {
                  rsaflag = true;
                }
              }
              if (rsaflag) {
                if (options.type === "ObjectExpression") {
                  var object = calObject(options);
                  if (object && object.modulusLength) {
                    if (Number.isInteger(object.modulusLength) && object.modulusLength < 2048) {
                      context.report({
                        node: node,
                        messageId: "SHORT_RSA_KEY",
                      });
                    }
                  }
                }
              }
            }
          }
        }
      },
      MemberExpression: function (node) { 
        if (usedFlag) {
          if (node.property.type === "Identifier") {
            var method = node.property.name;
            if (method === "RSA_NO_PADDING"){
              context.report({
                node: node,
                messageId: "RSA_NO_PADDING",
              });
            }
            if (method === "RSA_PKCS1_PADDING"){
              context.report({
                node: node,
                messageId: "RSA_PKCS1_PADDING",
              });
            }
          }
        }
      }
    };
  },
};
