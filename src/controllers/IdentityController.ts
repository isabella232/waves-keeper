import { IdentityService } from '../lib/IdentityService';
import { Config, loadConfig } from '../lib/configService';
import { CognitoUser } from 'amazon-cognito-identity-js';
import { GeeTest } from '../ui/components/pages/importEmail/geeTest';

interface Options {
  getNetworkCode: () => string;
}

const MAINNET = 87;
const TESTNET = 84;

export class IdentityController {
  private identity: IdentityService;
  private getNetworkCode: Options['getNetworkCode'];
  protected networkByte: number;
  protected identityConfig: { [MAINNET]?: Config; [TESTNET]?: Config } = {};

  constructor(opts: Options) {
    this.getNetworkCode = opts.getNetworkCode;
    // prefetch identity configuration for networks
    Promise.all([MAINNET, TESTNET].map(networkByte => loadConfig(networkByte)))
      .then(([mainnet, testnet]) => {
        this.identityConfig[MAINNET] = mainnet;
        this.identityConfig[TESTNET] = testnet;
      })
      .then(() => this.configure(this.getNetworkByte()));
  }

  private getNetworkByte() {
    return this.getNetworkCode().charCodeAt(0);
  }

  async getConfig() {
    await this.configure(this.getNetworkByte());
    return this.identityConfig[this.networkByte];
  }

  private async configure(networkByte: number) {
    if (!this.identity || this.networkByte != networkByte) {
      this.networkByte = this.getNetworkCode().charCodeAt(0);

      this.identity = new IdentityService();

      const config = await this.identityConfig[networkByte];
      this.identity.configure({
        apiUrl: config.identity.apiUrl,
        clientId: config.identity.cognito.clientId,
        userPoolId: config.identity.cognito.userPoolId,
        endpoint: config.identity.cognito.endpoint,
        geetestUrl: config.identity.geetest.url,
      });
    }
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
}
