import * as React from 'react';
import * as styles from './importEmail.module.css';
import cn from 'classnames';
import { Error } from '../../ui';

import { Trans } from 'react-i18next';
import { useAppDispatch, useAppSelector } from '../../../store';
import { IdentityService } from '../../../../lib/IdentityService';
import { loadConfig } from '../../../../lib/configService';
import { IUser, Login } from './login';
import { newAccountSelect } from '../../../actions';
import { PAGES } from '../../../pageConfig';

export const baseByNetwork = {
  mainnet: 'https://waves.exchange',
  testnet: 'https://testnet.waves.exchange',
};

export const idByNetwork = {
  mainnet: 'W',
  testnet: 'T',
};

interface Props {
  setTab: (newTab: string) => void;
}

export function ImportEmail({ setTab }: Props) {
  const dispatch = useAppDispatch();
  const accounts = useAppSelector(state => state.accounts);
  const networkId = useAppSelector(state => state.currentNetwork);
  const chainId = idByNetwork[networkId].charCodeAt(0);
  const [alreadyExists, setAlreadyExists] = React.useState<boolean>(false);
  const identity = React.useRef<IdentityService>(new IdentityService());

  React.useEffect(() => {
    loadConfig(chainId).then(config => {
      identity.current.configure({
        apiUrl: config.identity.apiUrl,
        clientId: config.identity.cognito.clientId,
        userPoolId: config.identity.cognito.userPoolId,
        endpoint: config.identity.cognito.endpoint,
        geetestUrl: config.identity.geetest.url,
      });
    });

    const script = document.createElement('script');
    script.src = 'geeTestCode.js';
    script.async = true;
    document.body.appendChild(script);

    return () => document.body.removeChild(script);
  }, []);

  const handleConfirm = React.useCallback(
    (userData: IUser) => {
      if (accounts.find(({ address }) => address === userData.address)) {
        setAlreadyExists(true);
        return;
      }

      dispatch(
        newAccountSelect({
          type: 'wx',
          name: userData.username,
          address: userData.address,
          publicKey: userData.publicKey,
          hasBackup: true,
        })
      );

      setTab(PAGES.ACCOUNT_NAME_SEED);
    },
    [accounts]
  );

  return (
    <div className={styles.root}>
      <h2 className={cn('margin1', 'title1')}>
        <Trans i18nKey="importEmail.importEmailTitle" />
      </h2>

      <p className={cn(styles.centered, 'margin1', 'tag1', 'disabled500')}>
        <Trans i18nKey="importEmail.importEmailDesc" />
      </p>

      <Login
        className="margin4"
        identity={identity.current}
        onConfirm={handleConfirm}
      />

      <Error className="center" show={alreadyExists}>
        <Trans i18nKey="importEmail.alreadyExists" />
      </Error>
    </div>
  );
}
