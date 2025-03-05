// Express middleware that validates Firebase ID Tokens passed in the Authorization HTTP header.
// The Firebase ID token needs to be passed as a Bearer token in the Authorization HTTP header like this:
// `Authorization: Bearer <Firebase ID Token>`.
// when decoded successfully, the ID Token content will be added as `req.user`.
import {type UserRecord, type DecodedIdToken, getAuth} from "firebase-admin/auth";
import type {Request, Response} from "express";

export interface WithUser {
  decodedIdToken?: DecodedIdToken;
  user?: UserRecord
}
interface Config {
  enableLogs?: boolean
  pathWhitelist?: Set<string>
  useCustomAuth?: (req: Request) => Promise<UserRecord | null>
}
const getIDToken = (req: Request, enableLogs: boolean) => {
  if (req.headers.authorization?.startsWith('Bearer ')) {
    if (enableLogs) {
      console.log('Found "Authorization" header');
    }
    // Read the ID Token from the Authorization header.
    return req.headers.authorization.split('Bearer ')[1];
  } else if (req.cookies?.__session) {
    if (enableLogs) {
      console.log('Found "__session" cookie');
    }
    // Read the ID Token from cookie.
    return req.cookies.__session;
  }
}
export const validateFirebaseIdToken = (config: Config = {}) => {
  return async (req: Request & WithUser, res: Response, next: () => void) => {
    if (config.pathWhitelist?.size > 0) {
      if (config.pathWhitelist.has(req.path)) {
        return next();
      }
      for (const path of Array.from(config.pathWhitelist)) {
        if (config.enableLogs) {
          console.log(`Found "${path}" ends with * ${path.endsWith("*")} testing ${req.path} against ${path.slice(0, -1)}: ${req.path.startsWith(path.slice(0, -1))}`);
        }
        if (path.endsWith("*")) {
          if (req.path.startsWith(path.slice(0, -1))) {
            return next();
          }
        }
      }
    }
    if (config.enableLogs) {
      console.log('Check if request is authorized with Firebase ID token', req.headers, req.cookies);
    }

    const userData: WithUser = {}
    try {
      const idToken = getIDToken(req, config.enableLogs)
      if (!idToken) {
        throw new Error("idToken is empty")
      }
      const decodedIdToken = await getAuth().verifyIdToken(idToken);
      if (config.enableLogs) {
        console.log('ID Token correctly decoded', decodedIdToken);
      }
      const user = await getAuth().getUser(decodedIdToken.uid)
      userData.decodedIdToken = decodedIdToken
      userData.user = user
    } catch (e) {
      if (config.enableLogs) {
        console.log(`Error while verifying Firebase ID token: `, e.message);
      }
    }
    if (!userData.user && config.useCustomAuth) {
      userData.user = await config.useCustomAuth(req);
      if (config.enableLogs) {
        console.log('Authorising with customAuth: ', userData.user ? "Success" : "Fail");
      }
    }
    if (userData.user) {
      Object.assign(req, userData)
      return next();
    }
    if (config.enableLogs) {
      console.error('No Firebase ID token was passed as a Bearer token in the Authorization header.',
        'Make sure you authorize your request by providing the following HTTP header:',
        'Authorization: Bearer <Firebase ID Token>',
        ', by passing a "__session" cookie or using customAuth');
    }
    res.status(403).send('Unauthorized');
  };
}
