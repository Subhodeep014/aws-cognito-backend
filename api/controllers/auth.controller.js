import { CognitoIdentityProviderClient, InitiateAuthCommand, SignUpCommand, ListUsersCommand, AdminGetUserCommand
    ,ConfirmSignUpCommand, ResendConfirmationCodeCommand
} from '@aws-sdk/client-cognito-identity-provider';
import { errorHandler } from '../utils/error.js';
import jwt from 'jsonwebtoken'
const client = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION });

export const signup = async (req, res, next) => {
    const { email, password, name } = req.body;
  console.log(email,password)
    try {
        // Check if the email already exists in the user pool
        const listUsersCommand = new ListUsersCommand({
            UserPoolId: process.env.COGNITO_USER_POOL_ID,
            Filter: `email = "${email}"`,
        });
        const listUsersResponse = await client.send(listUsersCommand);
  
        if (listUsersResponse.Users.length > 0) {
            return next(errorHandler(400, 'Email is already registered'));
        }
        const signUpCommand = new SignUpCommand({
            ClientId: process.env.COGNITO_CLIENT_ID,
            Username: email,
            Password: password,
            UserAttributes: [
            {
                Name: 'email',
                Value: email,
            },
            {
                Name: 'name',
                Value: name,
            },
        ],
      });
  
      const signUpResponse = await client.send(signUpCommand);  
  
      return res.status(200).json({
        message: 'Sign-up successful! Please check your email for the confirmation code.',
        userSub: signUpResponse.UserSub,
        data: signUpResponse
      });
    } catch (error) {
      console.error('Signup error:', error);
      return res.status(400).json({ success: false, message: error.message });
    }
};
  
export const confirmSignup = async (req, res, next) => {
  const { email, confirmationCode } = req.body;

  try {
    const confirmSignUpCommand = new ConfirmSignUpCommand({
      ClientId: process.env.COGNITO_CLIENT_ID,
      Username: email,
      ConfirmationCode: confirmationCode,
    });

    await client.send(confirmSignUpCommand);

    return res.status(200).json({ message: 'User confirmed successfully' });
  } catch (error) {
    console.error('Confirmation error:', error);
    if (error.name === 'ExpiredCodeException') {
      return res.status(400).json({ success: false, message: 'Confirmation code has expired. Please request a new one.' });
    }
    return res.status(400).json({ success: false, message: error.message });
  }
};
export const signin = async (req, res, next) => {
  const { email, password } = req.body;

  const authCommand = new InitiateAuthCommand({
    AuthFlow: 'USER_PASSWORD_AUTH',
    ClientId: process.env.COGNITO_CLIENT_ID,
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
    },
  });
  const listUsersCommand = new ListUsersCommand({
    UserPoolId: process.env.COGNITO_USER_POOL_ID,
    Filter: `email = "${email}"`,
  });
  const listUsersResponse = await client.send(listUsersCommand);

  if (!listUsersResponse.Users.length > 0) {
      return next(errorHandler(400, 'Wrong credential or user not exist!  '));
  }

  try {
    // Step 1: Authenticate user
    const authResponse = await client.send(authCommand);

    // Step 2: Extract tokens directly from Cognito's response
    const accessToken = authResponse.AuthenticationResult.AccessToken;
    const refreshToken = authResponse.AuthenticationResult.RefreshToken;
    const idToken = authResponse.AuthenticationResult.IdToken;
    // console.log(idToken)
    // Step 4: Decode ID token to get user info (name, email, etc.)
    const decodedIdToken = jwt.decode(idToken);


    // Step 5: Set tokens in cookies and return user info
    return res.status(200)
      .cookie('access_token', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
      })
      .cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
      })
      .json({
        message: 'Sign-in successful',
        name: decodedIdToken.name,
        email: decodedIdToken.email,
        userId: decodedIdToken["cognito:username"],
      });

  } 
  catch (error) {
    // Handle incorrect password case
    if (error.name === 'NotAuthorizedException') {
      return next(errorHandler(401, 'Incorrect email or password.'));
    }

    // Handle user not confirmed error
    if (error.name === 'UserNotConfirmedException') {
      return next(errorHandler(401, 'Please verify your email before signing in.'));
    }

    // Log and handle any other errors
    console.error('Authentication or confirmation failed:', error);
    return next(errorHandler(500, 'Something went wrong during sign-in.'));
  }
}

export const resendOTP = async (req, res, next) => {
  const { email } = req.body;

  try {
      const resendCommand = new ResendConfirmationCodeCommand({
          ClientId: process.env.COGNITO_CLIENT_ID,
          Username: email,
      });

      await client.send(resendCommand);

      return res.status(200).json({
          message: 'Confirmation code resent successfully. Please check your email.'
      });
  } catch (error) {
      console.error('Error resending confirmation code:', error);
      return res.status(400).json({ success: false, message: error.message });
  }
};

export const signout = async(req, res)=>{
  res.clearCookie("access_token");
  res.clearCookie("refresh_token");

  return res.status(200).json({message : "Signed out successfully"});
}
export const refreshAccessToken = async (req, res, next) => {
    const refreshToken = req.cookies.refresh_token;

    if (!refreshToken) {
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      return res.status(401).json({ success: false, message: 'No refresh token provided' });
    }

    try {
        const command = new InitiateAuthCommand({
            AuthFlow: 'REFRESH_TOKEN_AUTH',
            ClientId: process.env.COGNITO_CLIENT_ID,
            AuthParameters: {
                REFRESH_TOKEN: refreshToken,
            },
        });

        const response = await client.send(command);

        // Extract new access token
        const newAccessToken = response.AuthenticationResult.AccessToken;
        const newRefreshToken = response.AuthenticationResult.RefreshToken;

        // Set new access token in cookies

        res.cookie('access_token', newAccessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'Strict',
        });
    
        if (newRefreshToken) {
          res.cookie('refresh_token', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
          });
        }
    
        return res.status(200).json({ message: 'Access token refreshed successfully' });
    } catch (error) {
      console.error('Token refresh failed:', error);

      // Clear all cookies if refresh token is invalid or error occurs
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');

      return res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
    }
};


export const checkAuthStatus = async (req, res) => {
  const accessToken = req.cookies.access_token;

  if (!accessToken) {
    return res.status(401).json({ message: 'No access token found' });
  }

  try {
    // Validate the access token
    await client.send(new GetUserCommand({ AccessToken: accessToken }));
    return res.status(200).json({ message: 'Token is valid' });
  } catch (error) {
    console.error('Token validation error:', error);
    // Clear cookies if token is invalid or expired
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

export const checkUserConfirmationStatus = async (req, res) => {
  const accessToken = req.cookies.access_token;

  if (!accessToken) {
    return res.status(401).json({ message: 'No access token found' });
  }

  try {
    // Extract the user sub (subject) from the access token
    const decodedToken = jwt.decode(accessToken);
    const userSub = decodedToken.sub;

    // Get user details using AdminGetUserCommand
    const adminGetUserCommand = new AdminGetUserCommand({
      UserPoolId: process.env.COGNITO_USER_POOL_ID,
      Username: userSub,
    });
    
    const user = await client.send(adminGetUserCommand);
    
    if (user.UserConfirmed) {
      return res.status(200).json({ message: 'User is confirmed' });
    } else {
      return res.status(403).json({ message: 'User is not confirmed' });
    }
  } catch (error) {
    console.error('Error checking user confirmation status:', error);
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};