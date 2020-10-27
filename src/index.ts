// Express middleware that validates Firebase ID Tokens passed in the Authorization HTTP header.
// The Firebase ID token needs to be passed as a Bearer token in the Authorization HTTP header like this:
// `Authorization: Bearer <Firebase ID Token>`.
// when decoded successfully, the ID Token content will be added as `req.user`.
import * as admin from "firebase-admin";
import {Request, Response} from "express";

export interface WithUser {
  user?: admin.auth.DecodedIdToken;
}
interface Config {
  enableLogs?: boolean
}
export const validateFirebaseIdToken = (config: Config = {}) => {

  return async (req: Request & WithUser, res: Response, next: () => void) => {
    console.log('Check if request is authorized with Firebase ID token', req.headers, req.cookies);

    if ((!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) &&
      !(req.cookies && req.cookies.__session)) {
      if (config.enableLogs) {
        console.error('No Firebase ID token was passed as a Bearer token in the Authorization header.',
          'Make sure you authorize your request by providing the following HTTP header:',
          'Authorization: Bearer <Firebase ID Token>',
          'or by passing a "__session" cookie.');
      }
      res.status(403).send('Unauthorized');
      return;
    }

    let idToken;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      if (config.enableLogs) {
        console.log('Found "Authorization" header');
      }
      // Read the ID Token from the Authorization header.
      idToken = req.headers.authorization.split('Bearer ')[1];
    } else if (req.cookies) {
      if (config.enableLogs) {
        console.log('Found "__session" cookie');
      }
      // Read the ID Token from cookie.
      idToken = req.cookies.__session;
    } else {
      // No cookie
      res.status(403).send('Unauthorized');
      return;
    }

    try {
      const decodedIdToken = await admin.auth().verifyIdToken(idToken);
      if (config.enableLogs) {
        console.log('ID Token correctly decoded', decodedIdToken);
      }
      req.user = decodedIdToken;
      next();
      return;
    } catch (error) {
      if (config.enableLogs) {
        console.error('Error while verifying Firebase ID token:', error);
      }
      res.status(403).send('Unauthorized');
      return;
    }
  };
}