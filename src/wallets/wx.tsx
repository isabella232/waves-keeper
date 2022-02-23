import { BigNumber } from '@waves/bignumber';
import { Account, NetworkName } from '../accounts/types';
import { Wallet } from './wallet';
import { TSignData } from '@waves/signature-adapter';
import * as libCrypto from '@waves/ts-lib-crypto';
import * as create from 'parse-json-bignumber';
import { convertInvokeListWorkAround } from './utils';
import { InfoAdapter } from '../controllers/MessageController';
import { convert } from '@waves/money-like-to-node';
import { IdentityController } from '../controllers';

const { stringify } = create({ BigNumber });

export interface WxWalletInput {
  name: string;
  network: NetworkName;
  networkCode: string;
  publicKey: string;
  identity: IdentityController;
}

interface WxWalletData extends Account {
  publicKey: string;
}

export class WxWallet extends Wallet<WxWalletData> {
  private readonly _adapter: InfoAdapter;
  private identity: IdentityController;

  constructor({
    name,
    network,
    networkCode,
    publicKey,
    identity,
  }: WxWalletInput) {
    super({
      address: libCrypto.address({ publicKey }, networkCode),
      name,
      network,
      networkCode,
      publicKey: publicKey,
      type: 'wx',
    });

    this._adapter = new InfoAdapter(this.data);
    this.identity = identity;

    this.identity.getConfig().then(() => {
      this.identity.identity.currentUser =
        this.identity.identity.userPool.getCurrentUser();
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
