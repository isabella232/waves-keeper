import * as React from 'react';
import { SignInForm } from './signInForm';
import { CodeConfirmation } from './codeConfirmation';
import {
  AuthChallenge,
  CodeDelivery,
  IdentityService,
} from '../../../../lib/IdentityService';
import { getGeeTestToken } from './geeTest';
import { Seed } from '@waves/waves-transactions/dist/seedUtils';

export interface IUser {
  username: string;
  address: string;
  publicKey: string;
  seed: Seed;
}

type LoginStateType = 'sign-in' | 'confirm-sign-in';

type LoginProps = {
  className: string;
  identity: IdentityService;
  onConfirm(user: IUser): void;
};

export function Login({ className = '', identity, onConfirm }: LoginProps) {
  const [loginState, setLoginState] = React.useState<LoginStateType>('sign-in');
  const [codeDelivery, setCodeDelivery] = React.useState<CodeDelivery>();
  const [is2FAEnabled, setIs2FAEnabled] = React.useState(false);
  const userData = React.useRef<{ username: string; password: string }>();

  const handleSuccess = React.useCallback(() => {
    onConfirm({
      username: identity.getUsername(),
      address: identity.getUserAddress(),
      publicKey: identity.getUserPublicKey(),
      seed: identity.seed,
    });
  }, [identity, is2FAEnabled, onConfirm]);

  const signIn = React.useCallback(
    async (username: string, password: string): Promise<void> => {
      const geeTest = await getGeeTestToken(identity.geetestUrl);
      const cognitoUser = await identity.signIn(username, password, geeTest);
      const challengeName: AuthChallenge | void = (cognitoUser as any)
        .challengeName;

      switch (challengeName) {
        case 'SOFTWARE_TOKEN_MFA':
          setCodeDelivery({
            type: 'TOTP',
            destination: 'TOTP device',
          });
          setLoginState('confirm-sign-in');
          setIs2FAEnabled(true);
          break;
        default:
          handleSuccess();
      }
    },
    [handleSuccess, identity]
  );

  const confirmSignIn = React.useCallback(
    async (code: string): Promise<void> => {
      try {
        await identity.confirmSignIn(code, 'SOFTWARE_TOKEN_MFA');
        handleSuccess();
      } catch (e) {
        if (e && e.code === 'NotAuthorizedException' && userData.current) {
          await signIn(userData.current.username, userData.current.password);
        } else {
          throw e;
        }
      }
    },
    [codeDelivery, handleSuccess, identity, signIn]
  );

  React.useEffect(() => {
    if (loginState !== 'confirm-sign-in') {
      setCodeDelivery(undefined);
    }
  }, [loginState]);

  return (
    <div className={className}>
      {loginState == 'sign-in' && <SignInForm signIn={signIn} />}

      {loginState === 'confirm-sign-in' && (
        <CodeConfirmation
          codeDelivery={codeDelivery}
          confirmCode={confirmSignIn}
        />
      )}
    </div>
  );
}
