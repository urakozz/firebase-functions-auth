# firebase-functions-auth
Small library for the Firebase Cloud Functions to validate and parse user made as an Express middleware

# Install

```shell script
npm i -S firebase-functions-auth
```

# Example

### Cloud functions side
```typescript
import * as functions from 'firebase-functions';
import * as admin from "firebase-admin";
import * as express from "express";
import * as cors from "cors";
import * as cookieParser from "cookie-parser";
import {validateFirebaseIdToken, WithUser} from "firebase-functions-auth";

admin.initializeApp();
const app = express();

// Automatically allow cross-origin requests
app.use(cors({origin: true}));
app.use(cookieParser());
app.use(validateFirebaseIdToken({ enableLogs: true }));

app.post('/testFn', (req: express.Request & WithUser, res) => {
  const userId = req.user ? req.user.uid : "";
  // user id and other user data now is available here 

  res.status(200).json({status: "error", userId, user: req.user})
});
```

### Frontend client side

```typescript

// Example of the function to perform requests

type UserInterface = { idToken: string }
export const fetchRequest = (user: UserInterface, url: string, method: string) => fetch(`https://europe-west1-casefolio-live.cloudfunctions.net${url}`, {
  method: method, // *GET, POST, PUT, DELETE, etc.
  mode: 'cors',
  cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
  // credentials: 'same-origin', // include, *same-origin, omit
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${user.idToken}`,
  },
}).then((result) => {
  if (result.status === 403) {
    return {status: "error", message: "Unauthorized. Please refresh the page and try again."}
  }
  return result.json();
})
  .then((res) => {
    if (res.status === "error") {
      let message = "Unable to perform the action";
      if (res.message) {
        message += `: ${res.message}`;
        if (res.message.startsWith("Unauthorized")) {
          message = res.message;
        }
      }
      throw new Error(message)
    }
    return res;
  });

// Example call
fetchRequest({ idToken: "blabla"}, `/testFn`, "POST").then((res) => {
  console.log("Success", { res });
}).catch((e) => {
  console.error("Error: " + e.message)
})

// Aquiring idToken
import fb from "@firebase/app";
import "@firebase/auth";
import {FirebaseAuth, User} from "@firebase/auth-types";

const auth: FirebaseAuth = (fb as any).auth();

auth.onAuthStateChanged(async (fireUser: User | null) => {
  if (fireUser) {
    const idToken = await fireUser.getIdToken();
    // here it is
    console.log("idToken", { idToken });
  }
})
```
