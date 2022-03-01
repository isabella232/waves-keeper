import * as styles from '../../pages/styles/transactions.styl';
import * as React from 'react';
import { Trans } from 'react-i18next';
import { ApproveBtn, Button, BUTTON_TYPE, Modal } from '../../ui';
import cn from 'classnames';
import { Login } from '../../pages/importEmail/login';
import background from '../../../services/Background';

export function TxFooter({
  message,
  approve,
  reject,
  hideApprove,
  autoClickProtection,
}) {
  const isSend = message.broadcast;

  const [isActive, setIsActive] = React.useState(true);
  const [pending, setPending] = React.useState(false);

  const checksToSign = React.useCallback(() => {
    setPending(true);
    // todo session is valid?
    setIsActive(false);
  }, [isActive]);

  const readyToSign = React.useCallback(() => {
    background.identityUpdate().then(() => console.log('identity confirmed'));
    setIsActive(true);
    approve();
  }, [approve]);

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
            onClick={checksToSign}
            type={BUTTON_TYPE.SUBMIT}
            loading={pending}
            autoClickProtection={autoClickProtection}
          >
            <Trans
              i18nKey={isSend ? 'sign.confirmButton' : 'sign.signButton'}
            />
          </ApproveBtn>

          <Modal showModal={!isActive} animation={Modal.ANIMATION.FLASH}>
            <div className={cn('modal', 'cover')}>
              <div className="modal-form">
                <Button
                  className="modal-close"
                  onClick={() => setIsActive(false)}
                  type="transparent"
                />
                <h2 className={cn('margin1', 'title1')}>Auth required</h2>
                <Login
                  // todo fetch selectedAccount
                  userData={{ username: '', password: '' }}
                  onConfirm={readyToSign}
                />
              </div>
            </div>
          </Modal>
        </>
      )}
    </div>
  );
}
