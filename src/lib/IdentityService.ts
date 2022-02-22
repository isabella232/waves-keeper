import { libs, seedUtils } from '@waves/waves-transactions';
import {
  AuthenticationDetails,
  CognitoIdToken,
  CognitoUser,
  CognitoUserAttribute,
  CognitoUserPool,
  ICognitoStorage,
  ISignUpResult,
} from 'amazon-cognito-identity-js';

type IdentityUser = {
  address: string;
  publicKey: string;
  username: string;
};

export type SignUpResponse = ISignUpResult;

export type CodeDelivery = {
  type: 'SMS' | 'EMAIL' | string;
  destination: string;
};

export type MFAType = 'SMS_MFA' | 'SOFTWARE_TOKEN_MFA';

export type AuthChallenge =
  | 'SMS_MFA'
  | 'SOFTWARE_TOKEN_MFA'
  | 'NEW_PASSWORD_REQUIRED'
  | 'MFA_SETUP'
  | 'CUSTOM_CHALLENGE';

type IdentityServiceOptions = {
  apiUrl: string;
  userPoolId: string;
  clientId: string;
  endpoint: string;
  geetestUrl: string;
};

export class IdentityService {
  public geetestUrl = '';
  private readonly storage: ICognitoStorage = window.localStorage;
  userPool: CognitoUserPool | undefined = undefined;
  // private currentUser: CognitoUser | undefined = undefined;
  currentUser: CognitoUser | undefined = undefined;
  private identityUser: IdentityUser | undefined = undefined;
  private username = '';
  private readonly seed = seedUtils.Seed.create();
  private apiUrl = '';

  public configure({
    apiUrl,
    clientId,
    userPoolId,
    endpoint,
    geetestUrl,
  }: IdentityServiceOptions): void {
    this.apiUrl = apiUrl;

    this.userPool = new CognitoUserPool({
      UserPoolId: userPoolId,
      ClientId: clientId,
      Storage: this.storage,
      endpoint,
    });

    this.geetestUrl = geetestUrl;
  }

  public getUsername(): string {
    if (!this.username) {
      return '';
    }

    const [name, domain] = this.username.split('@');

    return `${name[0]}********@${domain}`;
  }

  public getUserAddress(): string {
    return this.identityUser ? this.identityUser.address : '';
  }

  public getUserPublicKey(): string {
    return this.identityUser ? this.identityUser.publicKey : '';
  }

  public async signIn(
    username: string,
    password: string,
    metaData?: {
      geetest_challenge: string;
      geetest_seccode: string;
      geetest_validate: string;
    }
  ): Promise<CognitoUser> {
    this.currentUser = undefined;
    this.identityUser = undefined;
    this.username = username;

    return new Promise<CognitoUser>((resolve, reject) => {
      if (!this.userPool) {
        return reject(new Error('No UserPool'));
      }

      const user = new CognitoUser({
        Username: username,
        Pool: this.userPool,
        Storage: this.storage,
      });

      this.currentUser = user;

      this.currentUser.authenticateUser(
        new AuthenticationDetails({
          Username: username,
          Password: password,
          ClientMetadata: {
            'custom:encryptionKey': this.seed.keyPair.publicKey,
            ...metaData,
          },
        }),
        {
          onSuccess: async () => {
            this.identityUser = await this.fetchIdentityUser();

            delete user['challengeName'];
            delete user['challengeParam'];
            resolve(user);
          },

          onFailure: err => {
            reject(err);
          },
          customChallenge: function (challengeParam) {
            user['challengeName'] = 'CUSTOM_CHALLENGE';
            user['challengeParam'] = challengeParam;
            resolve(user);
          },
          mfaRequired: function (challengeName, challengeParam) {
            user['challengeName'] = challengeName;
            user['challengeParam'] = challengeParam;
            resolve(user);
          },
          mfaSetup: function (challengeName, challengeParam) {
            user['challengeName'] = challengeName;
            user['challengeParam'] = challengeParam;
            resolve(user);
          },
          newPasswordRequired: function (userAttributes, requiredAttributes) {
            user['challengeName'] = 'NEW_PASSWORD_REQUIRED';
            user['challengeParam'] = {
              userAttributes: userAttributes,
              requiredAttributes: requiredAttributes,
            };
            resolve(user);
          },
          totpRequired: function (challengeName, challengeParam) {
            user['challengeName'] = challengeName;
            user['challengeParam'] = challengeParam;
            resolve(user);
          },
          selectMFAType: function (challengeName, challengeParam) {
            user['challengeName'] = challengeName;
            user['challengeParam'] = challengeParam;
            resolve(user);
          },
        }
      );
    });
  }

  public async confirmSignIn(code: string, mfaType: MFAType): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.currentUser) {
        return reject(new Error('Not authenticated'));
      }

      this.currentUser.sendMFACode(
        code,
        {
          onSuccess: async session => {
            if (this.currentUser) {
              delete this.currentUser['challengeName'];
              delete this.currentUser['challengeParam'];
            }

            if (session && !this.identityUser) {
              this.identityUser = await this.fetchIdentityUser();

              resolve();
            }
          },
          onFailure: err => {
            reject(err);
          },
        },
        mfaType,
        {
          'custom:encryptionKey': this.seed.keyPair.publicKey,
        }
      );
    });
  }

  public signOut(): Promise<void> {
    if (this.currentUser) {
      this.currentUser.signOut();
    }

    this.currentUser = undefined;
    this.identityUser = undefined;
    this.username = '';

    return Promise.resolve();
  }

  public deleteUser(): Promise<string | undefined> {
    return new Promise((resolve, reject) => {
      if (!this.currentUser) {
        return reject(new Error('Not authenticated'));
      }

      this.currentUser.deleteUser(async (err, result) => {
        if (err) {
          reject(err);
        } else {
          try {
            await this.signOut();
            resolve(result);
          } catch (e) {
            reject(e);
          }
        }
      });
    });
  }

  public async signBytes(bytes: Array<number> | Uint8Array): Promise<string> {
    await this.refreshSessionIsNeed();

    const signature = libs.crypto.base58Decode(
      libs.crypto.signBytes(this.seed.keyPair, bytes)
    );
    const response = await this.signByIdentity({
      payload: libs.crypto.base64Encode(bytes),
      signature: libs.crypto.base64Encode(signature),
    });

    return libs.crypto.base58Encode(
      libs.crypto.base64Decode(response.signature)
    );
  }

  private getIdToken(): CognitoIdToken {
    if (!this.currentUser) {
      throw new Error('Not authenticated');
    }

    const session = this.currentUser.getSignInUserSession();

    if (!session) {
      throw new Error('Not authenticated');
    }

    return session.getIdToken();
  }

  private refreshSessionIsNeed(): Promise<void> {
    const token = this.getIdToken();
    const payload = token.decodePayload();
    const currentTime = Math.ceil(Date.now() / 1000);
    const currentPublicKey = this.seed.keyPair.publicKey;
    const isValidTime = payload.exp - currentTime > 10;
    const isValidPublicKey =
      payload['custom:encryptionKey'] === currentPublicKey;

    if (isValidPublicKey && isValidTime) {
      return Promise.resolve();
    }

    return this.refreshSession();
  }

  private async refreshSession(): Promise<any> {
    const meta = { 'custom:encryptionKey': this.seed.keyPair.publicKey };

    return new Promise<any>((resolve, reject) => {
      if (!this.currentUser) {
        return reject(new Error('Not authenticated'));
      }

      this.currentUser.updateAttributes(
        [
          new CognitoUserAttribute({
            Name: 'custom:encryptionKey',
            Value: this.seed.keyPair.publicKey,
          }),
        ],
        err => {
          if (err) {
            return reject(err);
          }

          if (!this.currentUser) {
            return reject(new Error('Not authenticated'));
          }

          const session = this.currentUser.getSignInUserSession();

          if (!session) {
            return reject(new Error('Not authenticated'));
          }

          const resfeshToken = session.getRefreshToken();

          this.currentUser.refreshSession(
            resfeshToken,
            (err, data) => {
              if (err) {
                return reject(err);
              }

              resolve(data);
            },
            meta
          );
        },
        meta
      );
    });
  }

  private async fetchIdentityUser(): Promise<IdentityUser> {
    const token = this.getIdToken().getJwtToken();
    const itentityUserResponse = await fetch(`${this.apiUrl}/v1/user`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${token}`,
      },
    });

    return await itentityUserResponse.json();
  }

  private async signByIdentity(
    body: IdentitySignTxRequest
  ): Promise<IdentitySignTxResponse> {
    const token = this.getIdToken().getJwtToken();
    const response = await fetch(`${this.apiUrl}/v1/sign`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });

    return await response.json();
  }
}

type IdentitySignTxRequest = {
  payload: string;
  signature: string;
};

type IdentitySignTxResponse = {
  signature: string;
};
