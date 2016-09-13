var JWT = require('jsonwebtoken'),
    config = require('./config.js'),
    authUtils = require('./authUtils.js'),
    AWS = require('aws-sdk');

exports.handler = function(event, context) {
    console.log(event);

    // Get information about the function that is requested to be invoked.
    // Extract the HTTP method and the resource path from event.methodArn.
    var elements = authUtils.extractMethodAndPath(event.methodArn);
    var http_method = elements[0];
    var resource_path = elements[1];

    var accessToken = authUtils.extractAccessToken(event.authorizationToken);

    console.log('Client token: ' + accessToken);

    try {
        verifiedJwt = JWT.verify(accessToken, config.jwt.accessTokenSecret);
        console.log(verifiedJwt);

        // parse the ARN from the incoming event
        var apiOptions = {};
        var tmp = event.methodArn.split(':');
        var apiGatewayArnTmp = tmp[5].split('/');
        var awsAccountId = tmp[4];

        var policy = authUtils.generatePolicy(verifiedJwt.userId, 'Allow', event.methodArn);

        context.succeed(policy);

    } catch (ex) {
        console.log(ex, ex.stack);
        context.fail("Unauthorized");
    }
};
