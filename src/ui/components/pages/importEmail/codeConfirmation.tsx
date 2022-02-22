import * as React from 'react';
import { VerifyCodeComponent } from './verifyCodeComponent';
import { CodeDelivery } from '../../../../lib/IdentityService';
import { Trans } from 'react-i18next';
import cn from 'classnames';

type CodeConfirmationProps = {
  codeDelivery: CodeDelivery | undefined;
  confirmCode(code: string): Promise<void>;
};

export function CodeConfirmation({
  codeDelivery,
  confirmCode,
}: CodeConfirmationProps) {
  const [isPending, setIsPending] = React.useState<boolean>(false);

  const handleConfirmCode = React.useCallback(
    async (code: string): Promise<boolean> => {
      try {
        await confirmCode(code);

        return true;
      } catch (e) {
        return false;
      }
    },
    [confirmCode]
  );

  const destination = codeDelivery?.destination;

  return (
    <form className="margin4">
      <div className={cn('margin1', 'tag1', 'basic500', 'input-title')}>
        <Trans
          i18nKey="importEmail.verifyAccountDesc"
          values={{ destination }}
        />
      </div>

      <VerifyCodeComponent
        className="margin4"
        isPending={isPending}
        isCodeSent={Boolean(codeDelivery)}
        onPendingChange={setIsPending}
        onApplyCode={handleConfirmCode}
      />
    </form>
  );
}
