import {
  AuthenticationDetails,
  CognitoIdToken,
  CognitoUser,
  CognitoUserAttribute,
  CognitoUserPool,
  ICognitoStorage,
} from 'amazon-cognito-identity-js';
import { GeeTest } from '../ui/components/pages/importEmail/geeTest';
import { libs, seedUtils } from '@waves/waves-transactions';
import * as ObservableStore from 'obs-store';
import { WxWalletInput } from '../wallets/wx';

export type IdentityUser = {
  address: string;
  publicKey: string;
  uuid: string; // cognito user identifier
};

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
  cognitoSessions: string;
};

interface Options {
  getNetwork: () => AllNetworks;
  getSelectedAccount: () => WxWalletInput | any;
  initState: IdentityState;
}

function encrypt(object, password: string): string {
  const jsonObj = JSON.stringify(object);
  return seedUtils.encryptSeed(jsonObj, password);
}

function decrypt(encryptedText: string, password: string): any {
  try {
    if (!encryptedText) {
      return {};
    }
    const decryptedJson = seedUtils.decryptSeed(encryptedText, password);
    return JSON.parse(decryptedJson);
  } catch (e) {
    throw new Error('Invalid password');
  }
}

class IdentityStorage extends ObservableStore implements ICognitoStorage {
  public getState: () => IdentityState;
  public putState: (newState: Partial<IdentityState>) => void;
  public updateState: (partial: Partial<IdentityState>) => void;
  private memo = {};
  private password: string;

  constructor(initState: Partial<IdentityState>) {
    super(initState || {});
  }

  lock() {
    this.password = undefined;
  }

  unlock(password: string) {
    this.password = password;
  }

  getItem(key: string): string | null {
    return this.memo[key];
  }

  removeItem(key: string): void {
    delete this.memo[key];
  }

  setItem(key: string, value: string): void {
    this.memo[key] = value;
  }

  clear(): void {
    this.memo = {};
  }

  purge(): void {
    this.putState({});
    this.clear();
  }

  restore(userId: string) {
    const cognitoSessions = decrypt(
      this.getState().cognitoSessions,
      this.password
    );
    this.memo = cognitoSessions[userId] || {};
  }

  persist(userId: string) {
    const cognitoSessions = decrypt(
      this.getState().cognitoSessions,
      this.password
    );
    cognitoSessions[userId] = this.memo;
    this.updateState({
      cognitoSessions: encrypt(cognitoSessions, this.password),
    });
  }
}

export class IdentityController {
  protected getNetwork: () => IdentityNetworks;
  protected getSelectedAccount: () => WxWalletInput | any;
  protected config: IdentityConfig = {};
  private readonly networks: IdentityNetworks[] = ['mainnet', 'testnet'];
  private network: AllNetworks;
  // identity properties
  private readonly seed = seedUtils.Seed.create();
  private userPool: CognitoUserPool | undefined = undefined;
  private currentUser: CognitoUser | undefined = undefined;
  private identityUser: IdentityUser | undefined = undefined;
  store: IdentityStorage;

  constructor(opts: Options) {
    this.store = new IdentityStorage(opts.initState);

    this.getNetwork = () =>
      opts.getNetwork() === 'testnet' ? 'testnet' : 'mainnet';

    this.getSelectedAccount = opts.getSelectedAccount;

    Promise.all(this.networks.map(network => this.loadConfig(network)))
      // prefetch identity configuration for networks
      .then(configs => {
        this.networks.forEach((network, i) => {
          this.config[network] = configs[i];
        });
      })
      .then(() => this.configure());
  }

  initVault(password) {
    this.store.unlock(password);
  }

  deleteVault() {
    this.clearSession();
    this.store.purge();
  }

  lock() {
    this.store.lock();
  }

  unlock(password: string) {
    this.store.unlock(password);
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

  getConfig(): Config {
    return this.config[this.network];
  }

  configure() {
    const currentNetwork = this.getNetwork();
    this.store.clear();

    if (this.network != currentNetwork) {
      this.network = currentNetwork;

      const config = this.config[currentNetwork];
      this.userPool = new CognitoUserPool({
        UserPoolId: config.identity.cognito.userPoolId,
        ClientId: config.identity.cognito.clientId,
        Storage: this.store,
        endpoint: config.identity.cognito.endpoint,
      });
    }
  }

  async signIn(
    username: string,
    password: string,
    metaData: GeeTest
  ): Promise<CognitoUser> {
    this.clearSession();

    return new Promise<CognitoUser>((resolve, reject) => {
      if (!this.userPool) {
        return reject(new Error('No UserPool'));
      }

      const user = new CognitoUser({
        Username: username,
        Pool: this.userPool,
        Storage: this.store,
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
            this.identityUser.uuid = this.currentUser.getUsername();
            this.currentUser = undefined;

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
              this.identityUser.uuid = this.currentUser.getUsername();
              this.currentUser = undefined;

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

  private async fetchIdentityUser(): Promise<IdentityUser> {
    const token = this.getIdToken().getJwtToken();
    const cfg = this.getConfig();
    const identityUserResponse = await fetch(`${cfg.identity.apiUrl}/v1/user`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${token}`,
      },
    });

    return await identityUserResponse.json();
  }

  getIdentityUser(): IdentityUser {
    return this.identityUser;
  }

  persistSession(userId: string) {
    this.store.persist(userId);
  }

  updateSession() {
    this.persistSession(this.getSelectedAccount().uuid);
    this.clearSession();
  }

  async restoreSession(userId: string) {
    this.clearSession();
    // set current user session
    this.store.restore(userId);
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
        this.refreshSessionIsNeed()
          .then(data => {
            this.persistSession(userId);
            resolve(data);
          })
          .catch(err => reject(err));
      });
    });
  }

  private async refreshSessionIsNeed() {
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

  private async refreshSession() {
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

          const refreshToken = session.getRefreshToken();

          this.currentUser.refreshSession(
            refreshToken,
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

  clearSession() {
    this.currentUser = undefined;
    this.identityUser = undefined;
    this.store.clear();
  }

  removeSession(userId: string) {
    this.clearSession();
    this.persistSession(userId);
  }

  async signBytes(bytes: Array<number> | Uint8Array): Promise<string> {
    const userId = this.getSelectedAccount().uuid;
    await this.restoreSession(userId);

    const signature = libs.crypto.base58Decode(
      libs.crypto.signBytes(this.seed.keyPair, bytes)
    );
    const response = await this.signByIdentity({
      payload: libs.crypto.base64Encode(bytes),
      signature: libs.crypto.base64Encode(signature),
    });

    this.clearSession();

    return libs.crypto.base58Encode(
      libs.crypto.base64Decode(response.signature)
    );
  }

  private async signByIdentity(body: {
    payload: string;
    signature: string;
  }): Promise<{
    signature: string;
  }> {
    const token = this.getIdToken().getJwtToken();
    const cfg = this.getConfig();
    const response = await fetch(`${cfg.identity.apiUrl}/v1/sign`, {
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
}
