import * as styles from './importEmail.module.css';
import cn from 'classnames';
import { Trans } from 'react-i18next';
import { Button, Error, Input } from '../../ui';
import * as React from 'react';
import { useAppSelector } from '../../../store';
import { baseByNetwork } from './importEmail';

export function SignInForm({ signIn }) {
  const networkId = useAppSelector(state => state.currentNetwork);

  const [pending, setPenging] = React.useState<boolean>(false);
  const [errors, setErrors] = React.useState<Record<string, string | null>>({
    _form: null,
    emailRequired: null,
    passwordRequired: null,
  });
  const [email, setEmail] = React.useState<string>('asmelnikovse@gmail.com');
  const [password, setPassword] = React.useState<string>('hellow0rlD!');
  const mounted = React.useRef<boolean>(false);

  const handleEmailChange = React.useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      setEmail(event.target.value.trim());
      setErrors(prev => ({
        ...prev,
        _form: null,
        emailRequired: null,
      }));
    },
    []
  );

  const handleEmailBlur = React.useCallback(() => {
    setErrors(prev => ({
      ...prev,
      emailRequired:
        email.length === 0 || /.+@.+\..+/.test(email) === false
          ? 'Enter correct email'
          : null,
    }));
  }, [email]);

  const handlePasswordChange = React.useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      setPassword(event.target.value);
      setErrors(prev => ({
        ...prev,
        _form: null,
        passwordRequired: null,
      }));
    },
    []
  );

  const handlePasswordBlur = React.useCallback(() => {
    setErrors(prev => ({
      ...prev,
      passwordRequired: password.length === 0 ? 'Enter password' : null,
    }));
  }, [password.length]);

  const handleSubmit = React.useCallback(
    async event => {
      event.preventDefault();

      setPenging(true);

      try {
        await signIn(email, password);
      } catch (e) {
        if (e) {
          const limitExceededMessage =
            'You have exceeded incorrect username or password limit. If you have any problems, please contact support https://support.waves.exchange/.';

          setErrors(prev => ({
            ...prev,
            _form:
              e.message === limitExceededMessage
                ? 'Attempt limit exceeded, please try after some time.'
                : e.message || JSON.stringify(e),
          }));
        }
      } finally {
        if (mounted.current) {
          setPenging(false);
        }
      }
    },
    [email, password, signIn]
  );

  React.useEffect(() => {
    mounted.current = true;

    return (): void => {
      mounted.current = false;
    };
  });

  const isSubmitEnabled =
    Object.entries(errors).filter(([_key, value]) => Boolean(value)).length ===
    0;

  return (
    <form onSubmit={handleSubmit}>
      <div className="margin1">
        <div className={'tag1 basic500 input-title'}>
          <Trans i18nKey="importEmail.emailLabel" />
        </div>

        <Input
          data-testid="emailInput"
          value={email}
          spellCheck={false}
          onChange={handleEmailChange}
          onBlur={handleEmailBlur}
          error={errors.emailRequired}
          autoFocus
        />
        <Error show={errors.emailRequired != null}>
          {errors.emailRequired}
        </Error>
      </div>

      <div className="margin4">
        <div className={'tag1 basic500 input-title'}>
          <Trans i18nKey="importEmail.passwordLabel" />
        </div>

        <Input
          data-testid="passwordInput"
          type="password"
          value={password}
          onChange={handlePasswordChange}
          onBlur={handlePasswordBlur}
          error={errors.passwordRequired}
        />
        <Error show={errors.passwordRequired != null}>
          {errors.passwordRequired}
        </Error>
      </div>

      <div className="margin4">
        <Button
          className="fullwidth"
          data-testid="submitButton"
          type="submit"
          onClick={handleSubmit}
          disabled={pending || !isSubmitEnabled}
          loading={pending}
        >
          <Trans i18nKey="importEmail.continue" />
        </Button>

        <Error show={errors._form != null}>{errors._form}</Error>
      </div>

      <div className={cn(styles.footer, 'body3')}>
        <a
          rel="noopener noreferrer"
          className="margin1 link blue"
          href={`${baseByNetwork[networkId]}/sign-in/email`}
          target="_blank"
        >
          <Trans i18nKey="importEmail.forgotPassword" />
        </a>

        <div>
          <Trans i18nKey="importEmail.dontHaveAccount" />
          &nbsp;
          <a
            rel="noopener noreferrer"
            className="link blue"
            href={`${baseByNetwork[networkId]}/sign-up/email`}
            target="_blank"
          >
            <Trans i18nKey="importEmail.signUp" />
          </a>
        </div>
      </div>
    </form>
  );
}
