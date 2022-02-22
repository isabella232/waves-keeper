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

export async function loadConfig(networkByte: number): Promise<Config> {
  const env = networkByte === 84 ? 'testnet' : 'mainnet';
  const wavesNetworksResponse = await fetch(
    'https://configs.waves.exchange/web/networks.json'
  );
  const wavesNetworks: NetworkConfig[] = await wavesNetworksResponse.json();
  const envNetworkConfig = wavesNetworks.find(c => c.name === env);

  if (!envNetworkConfig) {
    throw new Error(`No network configuration found for ${env}`);
  }

  const featuresConfigResponse = await fetch(
    `${envNetworkConfig.configService.url}/${envNetworkConfig.configService.featuresConfigUrl}`
  );
  return await featuresConfigResponse.json();
}
