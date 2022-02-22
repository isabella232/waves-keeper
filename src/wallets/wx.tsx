import { BigNumber } from '@waves/bignumber';
import { Account, NetworkName } from '../accounts/types';
import { Wallet } from './wallet';
import { TSignData } from '@waves/signature-adapter';
import * as libCrypto from '@waves/ts-lib-crypto';
import * as create from 'parse-json-bignumber';
import { convertInvokeListWorkAround } from './utils';
import { InfoAdapter } from '../controllers/MessageController';
import { convert } from '@waves/money-like-to-node';
import { IdentityService } from '../lib/IdentityService';
import { loadConfig } from '../lib/configService';
import { CognitoUserSession } from 'amazon-cognito-identity-js';

const { stringify } = create({ BigNumber });

export interface WxWalletInput {
  name: string;
  network: NetworkName;
  networkCode: string;
  publicKey: string;
}

interface WxWalletData extends Account {
  publicKey: string;
}

export class WxWallet extends Wallet<WxWalletData> {
  private readonly _adapter: InfoAdapter;
  identity: IdentityService = new IdentityService();

  constructor({ name, network, networkCode, publicKey }: WxWalletInput) {
    super({
      address: libCrypto.address({ publicKey }, networkCode),
      name,
      network,
      networkCode,
      publicKey: publicKey,
      type: 'wx',
    });

    this._adapter = new InfoAdapter(this.data);

    loadConfig(networkCode.charCodeAt(0)).then(config => {
      this.identity.configure({
        apiUrl: config.identity.apiUrl,
        clientId: config.identity.cognito.clientId,
        userPoolId: config.identity.cognito.userPoolId,
        endpoint: config.identity.cognito.endpoint,
        geetestUrl: config.identity.geetest.url,
      });

      this.identity.currentUser = this.identity.userPool.getCurrentUser();
      this.restoreSession();
    });
  }

  async restoreSession(): Promise<CognitoUserSession> {
    return await new Promise((resolve, reject) => {
      this.identity.currentUser.getSession((err, session) => {
        if (err) {
          reject(err);
        }
        resolve(session);
      });
    });
  }

  getSeed(): string {
    throw new Error('Cannot get seed');
  }

  getPrivateKey(): string {
    throw new Error('Cannot get private key');
  }

  async signWavesAuth(data) {
    throw new Error('Not implemented yet');
  }

  async signCustomData(data) {
    throw new Error('Not implemented yet');
  }

  async signTx(tx: TSignData): Promise<string> {
    const signable = this._adapter.makeSignable(tx);
    const bytes = await signable.getBytes();

    const signature = await this.identity.signBytes(bytes);
    const signData = await signable.getSignData();

    const data = convert(
      { ...signData, proofs: [...(signData.proofs || []), signature] },
      (item: any) => new BigNumber(item)
    );
    convertInvokeListWorkAround(data);

    return stringify(data);
  }

  async signBytes(bytes: number[]): Promise<string> {
    throw new Error('Not implemented yet');
  }

  async signRequest(request: TSignData): Promise<string> {
    return this.signTx(request);
  }
}
