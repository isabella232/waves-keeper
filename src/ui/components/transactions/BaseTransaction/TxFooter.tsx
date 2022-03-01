import * as styles from '../../pages/styles/transactions.styl';
import * as React from 'react';
import { Trans } from 'react-i18next';
import { ApproveBtn, Button, BUTTON_TYPE, Modal } from '../../ui';
import cn from 'classnames';
import { Login } from '../../pages/importEmail/login';
import background from '../../../services/Background';
import { useAppSelector } from '../../../store';

export function TxFooter({
  message,
  approve,
  reject,
  hideApprove,
  autoClickProtection,
}) {
  const isSend = message.broadcast;

  const account = useAppSelector(state => state.selectedAccount);

  const [showModal, setShowModal] = React.useState(false);
  const [pending, setPending] = React.useState(false);

  const performSignTx = React.useCallback(() => approve(), [approve]);
  const beforeSignTx = React.useCallback(() => {
    if (account.type == 'wx') {
      setPending(true);
      background
        .identityRestore(account.username)
        .then(() => {
          performSignTx();
        })
        .catch(err => {
          console.log(err);
          setShowModal(true);
        });
    } else {
      performSignTx();
    }
  }, [performSignTx]);
  const readyToSignTx = React.useCallback(() => {
    background.identityUpdate().then(() => {
      setShowModal(false);
      performSignTx();
    });
  }, [performSignTx]);

  return (
    <div className={`${styles.txButtonsWrapper} buttons-wrapper`}>
      <Button
        data-testid="rejectButton"
        id="reject"
        onClick={reject}
        type={BUTTON_TYPE.WARNING}
      >
        <Trans i18nKey="sign.reject" />
      </Button>

      {!hideApprove && (
        <>
          <ApproveBtn
            id="approve"
            onClick={beforeSignTx}
            type={BUTTON_TYPE.SUBMIT}
            loading={pending}
            disabled={pending}
            autoClickProtection={autoClickProtection}
          >
            <Trans
              i18nKey={isSend ? 'sign.confirmButton' : 'sign.signButton'}
            />
          </ApproveBtn>

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
                  onConfirm={readyToSignTx}
                />
              </div>
            </div>
          </Modal>
        </>
      )}
    </div>
  );
}
