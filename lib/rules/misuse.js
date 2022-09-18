/**
 * @fileoverview crypto misuse
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
    type: 'suggestion', // `problem`, `suggestion`, or `layout`
    docs: {
      description: "crypto misuse",
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
      LESS_ITER: "Less than 1000 iterations",
      FIX_SALT: "Salt should be random",
      FIX_IV: "IV should be random",
      FIX_KEY: "Key should not be fixed",
    }
  },

  create(context) {
    var crypto;
    var ancestors;
    var googFlag = true;

    //var methodsMap = new Array();
    var identifierMap = new Array();
    var litealArray = new Array();
    var litealArrayLength = 0;

    const ITERMINIMUM = 1000;

    //API ref: https://google.github.io/closure-library/api/goog.crypt.html
    const cryptMethods = new Set([
      "goog.crypt.Sha1",
      "goog.crypt.Md5",
      "goog.crypt.Aes",
      "goog.crypt.pbkdf2",
      "goog.crypt.Arc4",
      "goog.crypt.Cbc",
      "goog.crypt.Ctr",
    ]);

    const directReportMethods = new Set([
      "Sha1",
      "Md5",
      "Aes",
      "Arc4",
      "goog.crypt.Sha1",
      "goog.crypt.Md5",
      "goog.crypt.Aes",
      "goog.crypt.Arc4",
    ]);

    //const Aes = goog.require('goog.crypt.Aes'); 
    //那么 Aes 是一个 module
    //module 同时也是一个 operator·
    var moduleMap = new Array();

    //const aes = new Aes(keyArray);
    //那么 aes 是一个 operator
    var operatorMap = new Array();

    function reportNodeMessageWithValue(node, value) {
      var message = null;
      switch (value) {
        case "Sha1":
          message = "SHA1";
          break;
        case "Aes":
          message = "ECB";
          break;
        case "Md5":
          message = "MD5";
          break;
        case "Arc4":
          message = "RC4";
          break;
        case "goog.crypt.Sha1":
          message = "SHA1";
          break;
        case "goog.crypt.Md5":
          message = "MD5";
          break;
        case "goog.crypt.Aes":
          message = "ECB";
          break;
        case "goog.crypt.Arc4":
          message = "RC4";
          break;
        default:
          break;
      }
      if (message) {
        context.report({
          node: node,
          messageId: message,
        });
      }
    }

    //传入的 Node 是一个 CallExpression
    function reportNodeMethodArgs(node, method) {
      if (method === "deriveKeySha1") {
        var args = node.arguments;
        if (args.length === 4) {
          var iter = args[2];
          if (iter.type === "Literal") {
            if (Number.isInteger(iter.value) && iter.value < ITERMINIMUM) {
              context.report({
                node: node,
                messageId: "LESS_ITER",
              });
            }
          } else if (iter.type === "Identifier" && identifierMap.hasOwnProperty(iter.name)) {
            var iterValue = litealArray[identifierMap[iter.name]];
            if (Number.isInteger(iterValue) && iterValue < ITERMINIMUM) {
              context.report({
                node: node,
                messageId: "LESS_ITER",
              });
            } 
          } else if (iter.type === "MemberExpression" && identifierMap.hasOwnProperty(iter.object.name)) {
            var target_object = litealArray[identifierMap[iter.object.name]];
            var target_key = iter.property.name;
            if (target_object.hasOwnProperty(target_key)) {
              var iterValue = target_object[target_key];
              if (Number.isInteger(iterValue) && iterValue < ITERMINIMUM) {
                context.report({
                  node: node,
                  messageId: "LESS_ITER",
                });
              }
            }
          }

          var salt = args[1];
          if (salt.type === "Literal") {
            context.report({
              node: node,
              messageId: "FIX_SALT",
            });
          } else if (salt.type === "Identifier" && identifierMap.hasOwnProperty(salt.name)) {
            var saltValue = litealArray[identifierMap[salt.name]];
            if (saltValue) {
              context.report({
                node: node,
                data: {
                  value: saltValue,
                },
                messageId: "FIX_SALT",
              });
            }
          }
        }
      }
      var operator = node.callee.object;
      if (operator.type === "Identifier" && operatorMap.hasOwnProperty(operator.name)) {
        var operatorValue = operatorMap[operator.name];
        //method:check arg location
        var targetMethods = new Array();
        var targetMethodAlerts = new Array();
        // FIX_IV and FIX_KEY error
        // AES 已经在 NewExpression 中检查过了
        if (operatorValue === "goog.crypt.Arc4" || operatorValue === "Arc4") {
          targetMethods["setKey"] = 0;
          targetMethodAlerts["setKey"] = "FIX_KEY";
        } else if (operatorValue === "goog.crypt.Cbc" || operatorValue === "Cbc"
          || operatorValue === "goog.crypt.Ctr" || operatorValue === "Ctr") {
          targetMethods["decrypt"] = 1;
          targetMethodAlerts["decrypt"] = "FIX_IV";
          targetMethods["encrypt"] = 1;
          targetMethodAlerts["encrypt"] = "FIX_IV";
        }
        var method = node.callee.property.name;
        if (targetMethods.hasOwnProperty(method)) {
          var args = node.arguments;
          if (args.length > targetMethods[method]) {
            var arg = args[targetMethods[method]];
            if (arg.type === "Literal") {
              context.report({
                node: node,
                data: {
                  value: arg.value,
                },
                messageId: targetMethodAlerts[method],
              });
            } else if (arg.type === "Identifier" && identifierMap.hasOwnProperty(arg.name)) {
              var argValue = litealArray[identifierMap[arg.name]];
              if (argValue) {
                context.report({
                  node: node,
                  data: {
                    value: argValue,
                  },
                  messageId: targetMethodAlerts[method],
                });
              }
            } else if (arg.type === "MemberExpression" && identifierMap.hasOwnProperty(arg.object.name)) {
              var target_object = litealArray[identifierMap[arg.object.name]];
              var target_key = arg.property.name;
              if (target_object.hasOwnProperty(target_key)) {
                var argValue = target_object[target_key];
                if (argValue) {
                  context.report({
                    node: node,
                    data: {
                      value: argValue,
                    },
                    messageId: targetMethodAlerts[method],
                  });
                }
              }
            }
          }
        }
      }
    }

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
        }
      }
      return object;
    }

    return {
      AssignmentExpression: function (node) {
        //也许可以增强提供运算
        try {
          if (node.left.type === "Identifier" && node.right.type === "Literal") {
            litealArrayLength = litealArray.push(node.right.value);
            identifierMap[node.left.name] = litealArrayLength - 1;
          } else if (node.left.type === "Identifier" && node.right.type === "ArrayExpression") {
            var array = calArray(node.right);
            if (array !== null) {
              litealArrayLength = litealArray.push(array);
              identifierMap[node.left.name] = litealArrayLength - 1;
            }
          } else if (node.left.type === "Identifier" && node.right.type === "Identifier") {
            if (identifierMap.hasOwnProperty(node.right.name)) {
              var index = identifierMap[node.right.name];
              identifierMap[node.left.name] = index;
            } else if (operatorMap.hasOwnProperty(node.right.name)){
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
          }
        } catch (e) {
          // console.log(e);
        }    
      },
      VariableDeclarator: function (node) {
        try {
          if (node.init.type === "Literal") {
            litealArrayLength = litealArray.push(node.init.value);
            identifierMap[node.id.name] = litealArrayLength - 1;
          } else if (node.init.type === "ArrayExpression") {
            var array = calArray(node.init);
            if (array !== null) {
              litealArrayLength = litealArray.push(array);
              identifierMap[node.id.name] = litealArrayLength - 1;
            }
          } else if (node.init.type === "Identifier") {
            if (identifierMap.hasOwnProperty(node.init.name)) {
              var index = identifierMap[node.init.name];
              identifierMap[node.id.name] = index;
            } else if (operatorMap.hasOwnProperty(node.init.name)){
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
          }
        } catch (e) {
          // console.log(e);
        }
      },
      CallExpression: function (node) {
        try {
          if (node.callee.type === "Identifier" && node.callee.name === "require") {
            if (node.arguments[0].type === "Literal") {
              if (node.arguments[0].value === "google-closure-library") {
                googFlag = true;
              }
            } else if (node.arguments[0].type === "Identifier") {
              if (identifierMap.hasOwnProperty(node.arguments[0].name) && identifierMap[node.arguments[0].name] !== null) {
                var index = identifierMap[node.arguments[0].name];
                if (litealArray[index] === "google-closure-library") {
                  googFlag = true;
                }
              }
            }
          }
        } catch (e) {
          // console.log(e);
        }
      },
      MemberExpression: function (node) {
        try {
                  // 如果找不到，也许是通过js文件引入的，所以这里可以不严格判断
        if (googFlag) {
          // 其实只能goog作为identifier，但是这里依旧这样判断
          if (node.object.type === "Identifier" && (node.property.name == "require" || node.property.name == "provide")) {
            ancestors = context.getAncestors();
            var ancestor = ancestors[ancestors.length - 1];
            var value;
            if (ancestor.arguments !== undefined){
              if (ancestor.arguments[0].type === "Identifier") {
                if (identifierMap.hasOwnProperty(ancestor.arguments[0].name) && identifierMap[ancestor.arguments[0].name] !== null) {
                  value = litealArray[identifierMap[ancestor.arguments[0].name]];
                }
              } else if (ancestor.arguments[0].type === "Literal") {
                value = ancestor.arguments[0].value;
              }
              if (cryptMethods.has(value)) {
                // messsage = cryptMethods[value];
                crypto = ancestor.callee.object.name;
                var root = ancestor.parent;
                if (root.type === "VariableDeclarator") {
                  // moduleSet.add(root.id.name);
                  moduleMap[root.id.name] = value;
                  operatorMap[root.id.name] = value;
                } else if (root.type === "AssignmentExpression") {
                  moduleMap[root.left.name] = value;
                  operatorMap[root.left.name] = value;
                }
              }
            }
          } else {
            var object = node.object;
            if (object.type === "Identifier" && object.name === crypto) {
              var parent = object.parent;
              var root = parent.parent;
              if (parent.property.name === "crypt") {
                var value = root.property.name;
                if (directReportMethods.has(value)) {
                  reportNodeMessageWithValue(node, value);
                }
                var call = root.parent.parent;
                if (call.type === "CallExpression") {
                  value = root.parent.property.name;
                  reportNodeMethodArgs(call, value);
                }
              }
            }
          }
        }
        if (node.object.type === "Identifier" && operatorMap.hasOwnProperty(node.object.name)) {
          var value = operatorMap[node.object.name];
          if (directReportMethods.has(value)) {
            reportNodeMessageWithValue(node, value);
          }
          if (node.parent.type === "CallExpression") {
            value = node.property.name;
            reportNodeMethodArgs(node.parent, value);
          }
        }
        } catch (e) {
          // console.log(e);
        }
      },
      NewExpression: function (node) {
        try {
          var parent = node.parent;
          if (parent.type === "VariableDeclarator"
            && node.callee.type === "Identifier"
            && moduleMap.hasOwnProperty(node.callee.name)) {
            operatorMap[parent.id.name] = moduleMap[node.callee.name];
            // AES会在new的时候传入key，所以这里需要判断
            if (moduleMap[node.callee.name] === "goog.crypt.Aes") {
              var args = node.arguments;
              if (args.length === 1) {
                if (args[0].type == "Literal") {
                  context.report({
                    node: node,
                    messageId: "FIX_KEY",
                  });
                } else if (args[0].type === "Identifier" && identifierMap.hasOwnProperty(args[0].name)) {
                  var keyValue = litealArray[identifierMap[args[0].name]];
                  if (keyValue) {
                    context.report({
                      node: node,
                      messageId: "FIX_KEY",
                    });
                  }
                } else if (args[0].type === "MemberExpression") {
                  var expression = args[0];
                  if (expression.object.type === "Identifier" && identifierMap.hasOwnProperty(expression.object.name)) {
                    var target_key = expression.object.name;
                    var target_value = expression.property.name;
                    var target_object = litealArray[identifierMap[target_key]];
                    if (target_object) {
                      if (target_object.hasOwnProperty(target_value)) {
                        var keyValue = target_object[target_value];
                        if (keyValue) {
                          context.report({
                            node: node,
                            messageId: "FIX_KEY",
                          });
                        }
                      }
                    }
                  }
                }
              }
            }
          } else if (parent.type === "AssignmentExpression"
            && parent.left.type === "Identifier"
            && moduleMap.hasOwnProperty(node.callee.name)) {
            operatorMap[parent.left.name] = moduleMap[node.callee.name];
            if (moduleMap[node.callee.name] === "goog.crypt.Aes") {
              var args = node.arguments;
              if (args.length === 1) {
                if (args[0].type == "Literal") {
                  context.report({
                    node: node,
                    messageId: "FIX_KEY",
                  });
                } else if (args[0].type === "Identifier" && identifierMap.hasOwnProperty(args[0].name)) {
                  var keyValue = litealArray[identifierMap[args[0].name]];
                  if (keyValue) {
                    context.report({
                      node: node,
                      messageId: "FIX_KEY",
                    });
                  }
                } else if (args[0].type === "MemberExpression") {
                  var expression = args[0];
                  if (expression.object.type === "Identifier" && identifierMap.hasOwnProperty(expression.object.name)) {
                    var target_key = expression.object.name;
                    var target_value = expression.property.name;
                    var target_object = litealArray[identifierMap[target_key]];
                    if (target_object) {
                      if (target_object.hasOwnProperty(target_value)) {
                        var keyValue = target_object[target_value];
                        if (keyValue) {
                          context.report({
                            node: node,
                            messageId: "FIX_KEY",
                          });
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        catch (e) {
          
        }
      },
    };
  },
};
