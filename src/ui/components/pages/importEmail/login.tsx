import * as React from 'react';
import { SignInForm } from './signInForm';
import { CodeConfirmation } from './codeConfirmation';
import {
  AuthChallenge,
  CodeDelivery,
  IdentityUser,
} from '../../../../controllers/IdentityController';
import { getGeeTestToken } from './geeTest';
import background from '../../../services/Background';

type LoginStateType = 'sign-in' | 'confirm-sign-in';

type LoginProps = {
  className: string;
  onConfirm(user: IdentityUser & { name: string }): void;
};

export function Login({ className = '', onConfirm }: LoginProps) {
  const [loginState, setLoginState] = React.useState<LoginStateType>('sign-in');
  const [codeDelivery, setCodeDelivery] = React.useState<CodeDelivery>();
  const [is2FAEnabled, setIs2FAEnabled] = React.useState(false);
  const userData = React.useRef<{ username: string; password: string }>();

  const handleSuccess = React.useCallback(() => {
    background.identityUser().then((identityUser: IdentityUser) => {
      const [name, domain] = userData.current.username.split('@');
      onConfirm({ ...identityUser, name: `${name[0]}*******@${domain}` });
    });
  }, [is2FAEnabled, onConfirm]);

  const signIn = React.useCallback(
    async (username: string, password: string): Promise<void> => {
      userData.current = { username, password };

      const config = await background.identityConfig();
      const geeTest = await getGeeTestToken(config.identity.geetest.url);
      const cognitoUser = await background.identitySignIn(
        username,
        password,
        geeTest
      );
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
    [handleSuccess]
  );

  const confirmSignIn = React.useCallback(
    async (code: string): Promise<void> => {
      try {
        await background.identityConfirmSignIn(code);
        handleSuccess();
      } catch (e) {
        if (e && e.code === 'NotAuthorizedException' && userData.current) {
          await signIn(userData.current.username, userData.current.password);
        } else {
          throw e;
        }
      }
    },
    [codeDelivery, handleSuccess, signIn]
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
