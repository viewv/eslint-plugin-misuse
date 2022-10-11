/**
 * @fileoverview Detect crypto misuse of the web crypto misuse API in code
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
      description: "Detect crypto misuse of the web crypto misuse API in code",
      recommended: false,
      url: null, // URL to the documentation page for this rule
    },
    fixable: null, // Or `code` or `whitespace`
    schema: [], // Add a schema if the rule has options
    messages: {
      SHA1: "SHA1 is not secure",
      MD5: "MD5 is not secure",
      RC4: "RC4 is not secure",
      ECB: "ECB is not secure",
      DES: "DES is not secure",
      LESS_ITER: "Less than 1000 iterations",
      FIX_SALT: "Salt should be random",
      FIX_IV: "IV should be random",
      FIX_KEY: "Key should not be fixed",
      WEAK_PASSWORD: "Weak password",
      TEST: "Test",
    }
  },

  create(context) {
    // variables should be defined here
    // var crypto;
    // var ancestors;
    // var useflag = true;

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

    operatorMap["crypto"] = "crypto";

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
        if (properties[i].type === "SpreadElement") {
          var spread = properties[i];
          if (spread.argument.type === "Identifier" && identifierMap.hasOwnProperty(spread.argument.name)) {
            var index = identifierMap[spread.argument.name];
            if (index !== null) {
              object[spread.argument.name] = litealArray[index];
            } 
          }
          continue;
        }
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
            if (target_object && target_object.hasOwnProperty(target_key)) {
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

    function checkIter(node, algorithmObject){
      if (algorithmObject && algorithmObject.hasOwnProperty('iterations')) {
        var iterations = algorithmObject["iterations"];
        if (Number.isInteger(iterations) && iterations < ITERMINIMUM){
          context.report({
            node: node,
            messageId: "LESS_ITER",
          });
        }
      }
    }

    //汇报调用中出现的问题，主要是检测函数和函数参数
    function reportWithCallNode(node, method, operator) {
      if (operator === "crypto" || operator === "subtle") {
        if (method === "digest") {
          var args = node.arguments;
          if (args.length >= 2) {
            var algorithm = args[0];
            if (algorithm.type === "Literal" && algorithm.value === "SHA-1") {
              context.report({
                node: node,
                messageId: "SHA1",
              });
            } else if (algorithm.type === "Identifier" && identifierMap.hasOwnProperty(algorithm.name)) {
              var algorithmValue = litealArray[identifierMap[algorithm.name]];
              if (algorithmValue === "SHA-1") {
                context.report({
                  node: node,
                  messageId: "SHA1",
                });
              }
            }
          }
        } else if (method === "generateKey") {
          var args = node.arguments;
          if (args.length >= 3) {
            var algorithm = args[0];
            var algorithmObject = null;
            if (algorithm.type === "Identifier" && identifierMap.hasOwnProperty(algorithm.name)) {
              algorithmObject = litealArray[identifierMap[algorithm.name]];
            } else if (algorithm.type === "ObjectExpression") {
              algorithmObject = calObject(algorithm);
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('hash')) {
              var hash = algorithmObject["hash"];
              if (hash === "SHA-1") {
                context.report({
                  node: node,
                  messageId: "SHA1",
                });
              } else if (typeof hash === "object" && hash.hasOwnProperty('name')) {
                if (hash["name"] === "SHA-1") {
                  context.report({
                    node: node,
                    messageId: "SHA1",
                  });
                }
              }
            }
            checkIter(node, algorithmObject);
          }
        } else if (method === "importKey") {
          var args = node.arguments;
          if (args.length >= 5) {
            var algorithm = args[2];
            var algorithmObject = null;
            if (algorithm.type === "Identifier" && identifierMap.hasOwnProperty(algorithm.name)) {
              algorithmObject = litealArray[identifierMap[algorithm.name]];
            } else if (algorithm.type === "ObjectExpression") {
              algorithmObject = calObject(algorithm);
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('hash')) {
              var hash = algorithmObject["hash"];
              if (hash === "SHA-1") {
                context.report({
                  node: node,
                  messageId: "SHA1",
                });
              } else if (typeof hash === "object" && hash.hasOwnProperty('name')) {
                if (hash['name'] === "SHA-1") {
                  context.report({
                    node: node,
                    messageId: "SHA1",
                  });
                }
              }
            }
            checkIter(node, algorithmObject);
          }
        } else if (method === "encrypt" || method === "decrypt") {
          var args = node.arguments;
          if (args.length >= 3) {
            var algorithm = args[0];
            var algorithmObject = null;
            if (algorithm.type === "Identifier" && identifierMap.hasOwnProperty(algorithm.name)) {
              algorithmObject = litealArray[identifierMap[algorithm.name]];
            } else if (algorithm.type === "ObjectExpression") {
              algorithmObject = calObject(algorithm);
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('name')) {
              var name = algorithmObject["name"];
              if (name === "AES_CTR") {
                if (algorithmObject.hasOwnProperty('counter')) {
                  var counter = algorithmObject["counter"];
                  if (counter) {
                    context.report({
                      node: node,
                      messageId: "FIX_IV",
                    });
                  }
                }
              } else if (name === "AES_CBC") {
                if (algorithmObject.hasOwnProperty('iv')) {
                  var iv = algorithmObject["iv"];
                  if (iv) {
                    context.report({
                      node: node,
                      messageId: "FIX_IV",
                    });
                  }
                }
              } else if (name === "AES_GCM") {
                if (algorithmObject.hasOwnProperty('iv')) {
                  var iv = algorithmObject["iv"];
                  if (iv) {
                    context.report({
                      node: node,
                      messageId: "FIX_IV",
                    });
                  }
                }
              }
              checkIter(node, algorithmObject);
            }
            var key = args[1];
            if (key.type === "Literal") {
              context.report({
                node: node,
                messageId: "FIX_KEY",
              });
            } else if (key.type === "Identifier" && identifierMap.hasOwnProperty(key.name)) {
              var keyValue = litealArray[identifierMap[key.name]];
              if (keyValue) {
                context.report({
                  node: node,
                  messageId: "FIX_KEY",
                });
              }
            }
          }
        } else if (method === "wrapKey") {
          var args = node.arguments;
          if (args.length >= 4) {
            var algorithm = args[3];
            var algorithmObject = null;
            if (algorithm.type === "Identifier" && identifierMap.hasOwnProperty(algorithm.name)) {
              algorithmObject = litealArray[identifierMap[algorithm.name]];
            } else if (algorithm.type === "ObjectExpression") {
              algorithmObject = calObject(algorithm);
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('iterations')) {
              var iterations = algorithmObject["iterations"];
              if (iterations && Number.isInteger(iterations) && iterations < 1000) {
                context.report({
                  node: node,
                  messageId: "FIX_ITER",
                });
              }
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('hash')) {
              var hash = algorithmObject["hash"];
              if (hash === "SHA-1") {
                context.report({
                  node: node,
                  messageId: "SHA1",
                });
              } else if (typeof hash === "object" && hash.hasOwnProperty('name')) {
                if (hash['name'] === "SHA-1") {
                  context.report({
                    node: node,
                    messageId: "SHA1",
                  });
                }
              }
            }
            checkIter(node, algorithmObject);
          }

        } else if (method === "unwrapKey") {
          var args = node.arguments;
          if (args.length >= 7) {
            var algorithm = args[3];
            var algorithmObject = null;
            if (algorithm.type === "Identifier" && identifierMap.hasOwnProperty(algorithm.name)) {
              algorithmObject = litealArray[identifierMap[algorithm.name]];
            } else if (algorithm.type === "ObjectExpression") {
              algorithmObject = calObject(algorithm);
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('iterations')) {
              var iterations = algorithmObject["iterations"];
              if (iterations && Number.isInteger(iterations) && iterations < 1000) {
                context.report({
                  node: node,
                  messageId: "FIX_ITER",
                });
              }
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('hash')) {
              var hash = algorithmObject["hash"];
              if (hash === "SHA-1") {
                context.report({
                  node: node,
                  messageId: "SHA1",
                });
              } else if (typeof hash === "object" && hash.hasOwnProperty('name')) {
                if (hash['name'] === "SHA-1") {
                  context.report({
                    node: node,
                    messageId: "SHA1",
                  });
                }
              }
            }
            checkIter(node, algorithmObject);
            algorithm = args[4];
            algorithmObject = null;
            if (algorithm.type === "Identifier" && identifierMap.hasOwnProperty(algorithm.name)) {
              algorithmObject = litealArray[identifierMap[algorithm.name]];
            } else if (algorithm.type === "ObjectExpression") {
              algorithmObject = calObject(algorithm);
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('iterations')) {
              var iterations = algorithmObject["iterations"];
              if (iterations && Number.isInteger(iterations) && iterations < 1000) {
                context.report({
                  node: node,
                  messageId: "FIX_ITER",
                });
              }
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('hash')) {
              var hash = algorithmObject["hash"];
              if (hash === "SHA-1") {
                context.report({
                  node: node,
                  messageId: "SHA1",
                });
              } else if (typeof hash === "object" && hash.hasOwnProperty('name')) {
                if (hash['name'] === "SHA-1") {
                  context.report({
                    node: node,
                    messageId: "SHA1",
                  });
                }
              }
            }
            checkIter(node, algorithmObject);
          }
        } else if (method === "sign") {
          var args = node.arguments;
          if (args.length >= 3) {
            var algorithm = args[0];
            var algorithmObject = null;
            if (algorithm.type === "Identifier" && identifierMap.hasOwnProperty(algorithm.name)) {
              algorithmObject = litealArray[identifierMap[algorithm.name]];
            } else if (algorithm.type === "ObjectExpression") {
              algorithmObject = calObject(algorithm);
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('iterations')) {
              var iterations = algorithmObject["iterations"];
              if (iterations && Number.isInteger(iterations) && iterations < 1000) {
                context.report({
                  node: node,
                  messageId: "FIX_ITER",
                });
              }
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('hash')) {
              var hash = algorithmObject["hash"];
              if (hash === "SHA-1") {
                context.report({
                  node: node,
                  messageId: "SHA1",
                });
              } else if (typeof hash === "object" && hash.hasOwnProperty('name')) {
                if (hash['name'] === "SHA-1") {
                  context.report({
                    node: node,
                    messageId: "SHA1",
                  });
                }
              }
            }
            checkIter(node, algorithmObject);
          }
        } else if (method === "deriveKey") {
          var args = node.arguments;
          if (args.length >= 5) {
            var algorithm = args[0];
            var algorithmObject = null;
            if (algorithm.type === "Identifier" && identifierMap.hasOwnProperty(algorithm.name)) {
              algorithmObject = litealArray[identifierMap[algorithm.name]];
            } else if (algorithm.type === "ObjectExpression") {
              algorithmObject = calObject(algorithm);
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('iterations')) {
              var iterations = algorithmObject["iterations"];
              if (iterations && Number.isInteger(iterations) && iterations < 1000) {
                context.report({
                  node: node,
                  messageId: "FIX_ITER",
                });
              }
            }
            if (algorithmObject && algorithmObject.hasOwnProperty('hash')) {
              var hash = algorithmObject["hash"];
              if (hash === "SHA-1") {
                context.report({
                  node: node,
                  messageId: "SHA1",
                });
              } else if (typeof hash === "object" && hash.hasOwnProperty('name')) {
                if (hash['name'] === "SHA-1") {
                  context.report({
                    node: node,
                    messageId: "SHA1",
                  });
                }
              }
            }
            checkIter(node, algorithmObject);
          }
        }
      }
    }

    function addOperatorWithMemberNode(node, name) {
      var invokeChain = new Array();
      var member = node;
      while (member.type === "MemberExpression") {
        invokeChain.push(member.property.name);
        member = member.object;
      }
      if (member.type === "Identifier") {
        invokeChain.push(member.name);
      }
      invokeChain.reverse();
      switch (invokeChain.length) {
        case 1:
          if (invokeChain[0] === "window") {
            operatorMap[name] = "window";
          } else if (invokeChain[0] === "crypto") {
            operatorMap[name] = "crypto";
          } else if (invokeChain[0] === "self") {
            operatorMap[name] = "self";
          }
          break;
        case 2:
          if (invokeChain[0] === "window" && invokeChain[1] === "crypto") {
            operatorMap[name] = "crypto";
          } else if (invokeChain[0] === "crypto" && invokeChain[1] === "subtle") {
            operatorMap[name] = "subtle";
          } else if (invokeChain[0] === "self" && invokeChain[1] === "crypto") {
            operatorMap[name] = "crypto";
          }
          break;
        case 3:
          if (invokeChain[0] === "window" && invokeChain[1] === "crypto" && invokeChain[2] === "subtle") {
            operatorMap[name] = "subtle";
          } else if (invokeChain[0] === "self" && invokeChain[1] === "window" && invokeChain[2] === "crypto") {
            operatorMap[name] = "crypto";
          } else if (invokeChain[0] === "self" && invokeChain[1] === "crypto" && invokeChain[2] === "subtle") {
            operatorMap[name] = "subtle";
          }
          break;
        case 4:
          if (invokeChain[0] === "self" && invokeChain[1] === "window" && invokeChain[2] === "crypto" && invokeChain[3] === "subtle") {
            operatorMap[name] = "subtle";
          }
          break;
        default:
          break;
      }
    }

    return {
      // 还需要考虑member的情况也就是y=x.z的情况，y相当于z的一个引用
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
        if (node.init){
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
        }
      },
      //还需要增加一种self.window.crypto的情况
      //肯定会调用crypto的方法，都是一个名字，所以可以这么做
      CallExpression: function (node) {
        if (node.callee.type === "MemberExpression") {
          var invokeSeq = new Array();
          var member = node.callee;
          while (member.type === "MemberExpression") {
            invokeSeq.push(member.property.name);
            member = member.object;
          }
          if (member.type === "Identifier") {
            invokeSeq.push(member.name);
          }
          var invokeSeqLength = invokeSeq.length;
          if (operatorMap.hasOwnProperty(invokeSeq[invokeSeqLength - 1])) {
            reportWithCallNode(node, invokeSeq[0], operatorMap[invokeSeq[invokeSeqLength - 1]]);
          } else if (invokeSeq[invokeSeqLength - 1] === "crypto") {
            var operator = "crypto";
            if (invokeSeqLength >= 2) {
              if (invokeSeq[invokeSeqLength - 2] === "subtle") {
                operator = "subtle";
              }
            }
            reportWithCallNode(node, invokeSeq[0], operator);
          } else if (invokeSeq[invokeSeqLength - 1] === "self") {
            if (invokeSeqLength >= 3) {
              if (invokeSeq[invokeSeqLength - 2] === "window" && invokeSeq[invokeSeqLength - 3] === "crypto") {
                reportWithCallNode(node, invokeSeq[0], "crypto");
              } else if (invokeSeq[invokeSeqLength - 2] === "crypto") {
                reportWithCallNode(node, invokeSeq[0], "crypto");
              }
            } else if (invokeSeqLength >= 2) {
              if (invokeSeq[invokeSeqLength - 2] === "crypto") {
                reportWithCallNode(node, invokeSeq[0], "crypto");
              }
            }
          } else if (invokeSeq[invokeSeqLength - 1] === "window") {
            if (invokeSeqLength >= 2) {
              if (invokeSeq[invokeSeqLength - 2] === "crypto") {
                reportWithCallNode(node, invokeSeq[0], "crypto");
              }
            }
          }
        }
      },
    };
  },
};
