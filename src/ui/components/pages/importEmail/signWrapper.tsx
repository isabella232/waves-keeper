import { useAppSelector } from '../../../store';
import * as React from 'react';
import background from '../../../services/Background';
import { Button, Modal } from '../../ui';
import cn from 'classnames';
import { Login } from './login';

type Props = {
  onConfirm: () => void;
  children: (renderProps: {
    onPrepare: () => void;
    pending: boolean;
  }) => React.ReactChild;
};

export function SignWrapper({ onConfirm, children }: Props) {
  const account = useAppSelector(state => state.selectedAccount);

  const [showModal, setShowModal] = React.useState(false);
  const [pending, setPending] = React.useState(false);

  const onPrepare = React.useCallback(() => {
    if (account.type !== 'wx') {
      onConfirm();
      return;
    }

    setPending(true);
    background
      .identityRestore(account.username)
      .then(() => {
        onConfirm();
      })
      .catch(() => {
        setShowModal(true);
      });
  }, [onConfirm]);

  const onReady = React.useCallback(() => {
    background.identityUpdate().then(() => {
      setShowModal(false);
      onConfirm();
    });
  }, [onConfirm]);

  return (
    <>
      {children({ onPrepare, pending })}

      {account.type === 'wx' && (
        <Modal showModal={showModal} animation={Modal.ANIMATION.FLASH}>
          <div className={cn('modal', 'cover')}>
            <div className="modal-form">
              <Button
                className="modal-close"
                onClick={() => {
                  setShowModal(false);
                  setPending(false);
                }}
                type="transparent"
              />
              <h2 className={cn('margin1', 'title1')}>Auth required</h2>
              <Login
                // todo fetch selectedAccount
                userData={{ username: '', password: '' }}
                onConfirm={onReady}
              />
            </div>
          </div>
        </Modal>
      )}
    </>
  );
}
