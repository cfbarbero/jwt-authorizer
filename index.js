var JWT = require('jsonwebtoken'),
    config = require('./config.js'),
    // AuthPolicy = require('./AuthPolicy.js'),
    AWS = require('aws-sdk');

var BEARER_TOKEN_PATTERN = /^Bearer[ ]+([^ ]+)[ ]*$/i;

// A function to extract an access token from Authorization header.
//
// This function assumes the value complies with the format described
// in "RFC 6750, 2.1. Authorization Request Header Field". For example,
// if "Bearer 123" is given to this function, "123" is returned.
function extractAccessToken(authorization) {
    // If the value of Authorization header is not available.
    if (!authorization) {
        // No access token.
        return null;
    }

    // Check if it matches the pattern "Bearer {access-token}".
    var result = BEARER_TOKEN_PATTERN.exec(authorization);

    // If the Authorization header does not match the pattern.
    if (!result) {
        // No access token.
        return null;
    }

    // Return the access token.
    return result[1];
}

// A function to extract the HTTP method and the resource path
// from event.methodArn.
function extractMethodAndPath(arn) {
    // The value of 'arn' follows the format shown below.
    //   arn:aws:execute-api:<regionid>:<accountid>:<apiid>/<stage>/<method>/<resourcepath>"
    // See 'Enable Amazon API Gateway Custom Authorization' for details.
    //   http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html

    // Check if the value of 'arn' is available just in case.
    if (!arn) {
        // HTTP method and a resource path are not available.
        return [null, null];
    }

    var arn_elements = arn.split(':', 6);
    var resource_elements = arn_elements[5].split('/', 4);
    var http_method = resource_elements[2];
    var resource_path = resource_elements[3];

    // Return the HTTP method and the resource path as a string array.
    return [http_method, resource_path];
}

function generatePolicy(principalId, effect, resource) {
    return {
        principalId: principalId,
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: effect,
                Resource: resource
            }]
        }
    };
}

exports.handler = function(event, context) {
    console.log(event);

    // Get information about the function that is requested to be invoked.
    // Extract the HTTP method and the resource path from event.methodArn.
    var elements = extractMethodAndPath(event.methodArn);
    var http_method = elements[0];
    var resource_path = elements[1];

    var accessToken = extractAccessToken(event.authorizationToken);

    console.log('Client token: ' + accessToken);

    try {
        verifiedJwt = JWT.verify(accessToken, config.jwt.accessTokenSecret);
        console.log(verifiedJwt);

        // parse the ARN from the incoming event
        var apiOptions = {};
        var tmp = event.methodArn.split(':');
        var apiGatewayArnTmp = tmp[5].split('/');
        var awsAccountId = tmp[4];

        var policy = generatePolicy(verifiedJwt.userId, 'Allow', event.methodArn);

        context.succeed(policy);

    } catch (ex) {
        console.log(ex, ex.stack);
        context.fail("Unauthorized");
    }
};
