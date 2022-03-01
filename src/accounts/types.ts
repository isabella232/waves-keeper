export type AccountType = 'seed' | 'encodedSeed' | 'privateKey' | 'wx';
export type NetworkName = 'mainnet' | 'testnet' | 'stagenet' | 'custom';

export interface Account {
  address: string;
  lastUsed?: number;
  name: string;
  network: NetworkName;
  networkCode: string;
  publicKey: string;
  type: AccountType;
  username?: string;
}

export type KeystoreAccount = Pick<
  Account,
  'address' | 'name' | 'networkCode'
> &
  (
    | { type?: 'seed'; seed: string }
    | { type: 'encodedSeed'; encodedSeed: string }
    | { type: 'privateKey'; privateKey: string }
    | { type: 'wx'; publicKey: string; address: string }
  );

export type KeystoreProfiles = Record<
  NetworkName,
  { accounts: KeystoreAccount[] }
>;
