import { GetUserCommand } from '@aws-sdk/client-cognito-identity-provider';
import jwt from 'jsonwebtoken';
import { errorHandler } from '../utils/error.js';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';

const client = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION });

export const verifyUser = async (req, res, next) => {
  const accessToken = req.cookies.access_token;

  if (!accessToken) {
    return next(errorHandler(401, 'Unauthorized, no access token'));
  }

  try {
    // Step 1: Decode the access token to extract user information
    const decodedToken = jwt.decode(accessToken);
    
    if (!decodedToken) {
      return next(errorHandler(403, 'Invalid token format'));
    }

    const { sub: userId, email } = decodedToken;  // Extract user ID and email from the token

    // Step 2: Validate the token using AWS Cognito
    const getUserCommand = new GetUserCommand({
      AccessToken: accessToken,
    });

    const userData = await client.send(getUserCommand);

    // Step 3: Attach user info to the request object
    req.user = {
      userId, // Cognito User's unique identifier
      email, // User's email
      name: userData.UserAttributes.find(attr => attr.Name === 'name').Value, // User's name
    };

    // Step 4: Proceed to the next middleware/controller
    next();
  } catch (error) {
    console.error('Token validation error:', error);
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return next(errorHandler(403, 'Invalid or expired access token'));
  }
};
