import * as React from 'react';
import * as styles from './importEmail.module.css';
import cn from 'classnames';
import { Error } from '../../ui';

import { Trans } from 'react-i18next';
import { useAppDispatch, useAppSelector } from '../../../store';
import { Login } from './login';
import { newAccountSelect } from '../../../actions';
import { PAGES } from '../../../pageConfig';
import background from '../../../services/Background';

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
  const [alreadyExists, setAlreadyExists] = React.useState<boolean>(false);

  React.useEffect(() => {
    background.identityClear();

    const script = document.createElement('script');
    script.src = 'geeTestCode.js';
    script.async = true;
    document.body.appendChild(script);

    return () => document.body.removeChild(script);
  }, []);

  const handleConfirm = React.useCallback(
    userData => {
      if (accounts.find(({ address }) => address === userData.address)) {
        setAlreadyExists(true);
        return;
      }

      dispatch(
        newAccountSelect({
          type: 'wx',
          name: userData.name,
          address: userData.address,
          publicKey: userData.publicKey,
          username: userData.username,
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

      <Login className="margin4" onConfirm={handleConfirm} />

      <Error className="center" show={alreadyExists}>
        <Trans i18nKey="importEmail.alreadyExists" />
      </Error>
    </div>
  );
}
