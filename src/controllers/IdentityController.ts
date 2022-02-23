import { IdentityService } from '../lib/IdentityService';
import { CognitoUser, CognitoUserSession } from 'amazon-cognito-identity-js';
import { GeeTest } from '../ui/components/pages/importEmail/geeTest';

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

interface Options {
  getNetwork: () => AllNetworks;
}

export class IdentityController {
  private identity: IdentityService;
  protected getNetwork: () => IdentityNetworks;
  protected network: AllNetworks;
  private networks: IdentityNetworks[] = ['mainnet', 'testnet'];
  protected config: IdentityConfig = {};

  constructor(opts: Options) {
    this.getNetwork = () =>
      opts.getNetwork() === 'testnet' ? 'testnet' : 'mainnet';

    // prefetch identity configuration for networks
    Promise.all(this.networks.map(network => this.loadConfig(network)))
      .then(configs => {
        this.networks.forEach((network, i) => {
          this.config[network] = configs[i];
        });
      })
      .then(() => this.configure(this.getNetwork()));
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
    if (!this.identity || this.network != network) {
      this.network = this.getNetwork();
      this.identity = new IdentityService();

      const config = await this.config[network];
      this.identity.configure({
        apiUrl: config.identity.apiUrl,
        clientId: config.identity.cognito.clientId,
        userPoolId: config.identity.cognito.userPoolId,
        endpoint: config.identity.cognito.endpoint,
        geetestUrl: config.identity.geetest.url,
      });
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
    geeTest: GeeTest
  ): Promise<CognitoUser> {
    return this.identity.signIn(username, password, geeTest);
  }

  async confirmSignIn(
    code: string,
    challengeName: 'SOFTWARE_TOKEN_MFA' = 'SOFTWARE_TOKEN_MFA'
  ) {
    return this.identity.confirmSignIn(code, challengeName);
  }

  async identityUser() {
    return {
      address: this.identity.getUserAddress(),
      publicKey: this.identity.getUserPublicKey(),
      username: this.identity.getUsername(),
    };
  }

  async restoreSession(): Promise<CognitoUserSession> {
    // restores user session tokens from storage
    return new Promise((resolve, reject) => {
      this.identity.currentUser.getSession((err, session) => {
        if (err) {
          reject(err);
        }
        resolve(session);
      });
    });
  }

  async signBytes(bytes: Array<number> | Uint8Array) {
    return this.identity.signBytes(bytes);
  }
}
