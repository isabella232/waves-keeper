import {
  AuthenticationDetails,
  CognitoIdToken,
  CognitoUser,
  CognitoUserAttribute,
  CognitoUserPool,
  CognitoUserSession,
  ICognitoStorage,
  ISignUpResult,
} from 'amazon-cognito-identity-js';
import { GeeTest } from '../ui/components/pages/importEmail/geeTest';
import { libs, seedUtils } from '@waves/waves-transactions';
import * as ObservableStore from 'obs-store';

export type IdentityUser = {
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

type IdentitySignTxRequest = {
  payload: string;
  signature: string;
};

type IdentitySignTxResponse = {
  signature: string;
};

export type Config = {
  identity: {
    apiUrl: string;
    cognito: {
      clientId: string;
      userPoolId: string;
      endpoint: string;
    };
    geetest: {
      url: string;
    };
  };
};

type ConfigUrls = {
  url: string;
  featuresConfigUrl: string;
  notificationsUrl: string;
  updatesUrl: string;
  leasing: string;
  feeConfigUrl: string;
};

type NetworkConfig = {
  name: string;
  configService: ConfigUrls;
};

type IdentityNetworks = 'mainnet' | 'testnet';
type AllNetworks = 'mainnet' | 'testnet' | 'stagenet' | 'custom';

type IdentityConfig = Partial<{
  [K in IdentityNetworks]: Config;
}>;

type IdentityState = {
  session: string;
};

interface Options {
  getNetwork: () => AllNetworks;
  initState: IdentityState;
}

class IdentityStorage implements ICognitoStorage {
  private dataMemory = {};

  clear(): void {
    this.dataMemory = {};
  }

  getItem(key: string): string | null {
    return this.dataMemory[key];
  }

  removeItem(key: string): void {
    delete this.dataMemory[key];
  }

  setItem(key: string, value: string): void {
    this.dataMemory[key] = value;
  }
}

export class IdentityController {
  protected getNetwork: () => IdentityNetworks;
  private network: AllNetworks;
  private readonly networks: IdentityNetworks[] = ['mainnet', 'testnet'];
  protected config: IdentityConfig = {};
  public store: ObservableStore;
  // identity properties
  private storage: ICognitoStorage;
  private password: string;
  private userPool: CognitoUserPool | undefined = undefined;
  private currentUser: CognitoUser | undefined = undefined;
  private identityUser: IdentityUser | undefined = undefined;
  private username = '';
  private readonly seed = seedUtils.Seed.create();
  private apiUrl = '';
  public geetestUrl = '';

  constructor(opts: Options) {
    this.store = new ObservableStore(opts.initState);

    this.getNetwork = () =>
      opts.getNetwork() === 'testnet' ? 'testnet' : 'mainnet';

    // prefetch identity configuration for networks
    Promise.all(this.networks.map(network => this.loadConfig(network))).then(
      configs => {
        this.networks.forEach((network, i) => {
          this.config[network] = configs[i];
        });
      }
    );
  }

  lock() {
    console.log('identity locked');
    this.apiUrl = '';
    this.storage = undefined;
    this.userPool = undefined;
    this.currentUser = undefined;
    this.geetestUrl = '';
  }

  unlock(password: string) {
    console.log('identity unlocked');
    // todo decrypt this.storage
    this.storage = window.localStorage;
    this.configure(this.getNetwork());
  }

  private async loadConfig(network: AllNetworks): Promise<Config> {
    const wavesNetworksResponse = await fetch(
      'https://configs.waves.exchange/web/networks.json'
    );
    const wavesNetworks: NetworkConfig[] = await wavesNetworksResponse.json();
    const envNetworkConfig = wavesNetworks.find(c => c.name === network);

    if (!envNetworkConfig) {
      throw new Error(`No network configuration found for ${network}`);
    }

    const featuresConfigResponse = await fetch(
      `${envNetworkConfig.configService.url}/${envNetworkConfig.configService.featuresConfigUrl}`
    );
    return await featuresConfigResponse.json();
  }

  private async configure(network: AllNetworks) {
    if (this.network != network) {
      this.network = this.getNetwork();

      const config = await this.config[network];

      this.apiUrl = config.identity.apiUrl;

      this.userPool = new CognitoUserPool({
        UserPoolId: config.identity.cognito.userPoolId,
        ClientId: config.identity.cognito.clientId,
        Storage: this.storage,
        endpoint: config.identity.cognito.endpoint,
      });

      this.geetestUrl = config.identity.geetest.url;
    }
  }

  async getConfig() {
    // TODO reconfigure on account switch
    await this.configure(this.getNetwork());
    return this.config[this.network];
  }

  async signIn(
    username: string,
    password: string,
    metaData: GeeTest
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

  async confirmSignIn(
    code: string,
    mfaType: MFAType = 'SOFTWARE_TOKEN_MFA'
  ): Promise<void> {
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

  private async refreshSessionIsNeed(): Promise<void> {
    await this.restoreSession();

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

  private async restoreSession(): Promise<CognitoUserSession> {
    this.currentUser = this.userPool.getCurrentUser();
    // restores user session tokens from storage
    return new Promise((resolve, reject) => {
      if (!this.currentUser) {
        reject(new Error('Not authenticated'));
      }

      this.currentUser.getSession((err, session) => {
        if (err) {
          reject(err);
        }
        resolve(session);
      });
    });
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

  async getIdentityUser() {
    if (!this.username) {
      return '';
    }

    const [name, domain] = this.username.split('@');

    return {
      address: this.identityUser ? this.identityUser.address : '',
      publicKey: this.identityUser ? this.identityUser.publicKey : '',
      username: `${name[0]}********@${domain}`,
    };
  }
}
