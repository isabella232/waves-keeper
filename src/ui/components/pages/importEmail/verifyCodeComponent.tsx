import * as React from 'react';
import * as styles from './verifyCodeComponent.module.css';
import { Button, Error, Input } from '../../ui';
import { Trans } from 'react-i18next';

type VerifyCodeComponentProps = {
  className: string;
  isPending: boolean;
  codeLength?: number;
  timerTime?: number;
  isCodeSent?: boolean;
  onPendingChange(isPending: boolean): void;
  onApplyCode?(code: string): Promise<boolean>;
};

export const VerifyCodeComponent: React.FC<VerifyCodeComponentProps> = ({
  className,
  codeLength = 6,
  onApplyCode,
  onPendingChange: onPending,
  isPending,
}) => {
  const [isIncorrectCode, setIsIncorrectCode] = React.useState<boolean>(false);
  const [isFilled, setIsFilled] = React.useState<boolean>(false);
  const refs = React.useMemo((): Array<React.RefObject<HTMLInputElement>> => {
    return new Array(codeLength).fill(undefined).map(() => React.createRef());
  }, [codeLength]);
  const [values, setValues] = React.useState<Array<string>>(refs.map(() => ''));
  const [autoFocusIndex, setAutoFocusIndex] = React.useState<number>(0);

  React.useEffect(() => {
    let mounted = true;

    if (values.length < codeLength || values.some(v => !v)) {
      setIsFilled(false);

      return;
    }

    onPending(true);

    if (typeof onApplyCode === 'function') {
      const code = values.join('');

      onApplyCode(code)
        .then(result => {
          if (!mounted) {
            return;
          }
          setIsFilled(true);
          onPending(false);
          setIsIncorrectCode(!result);
        })
        .catch(() => {
          if (!mounted) {
            return;
          }
          setIsFilled(true);
          onPending(false);
          setIsIncorrectCode(true);
        });
    } else {
      setIsFilled(true);
      onPending(false);
    }

    return (): void => {
      mounted = false;
    };
  }, [values, onApplyCode, refs, codeLength, onPending]);

  const onInputClick = React.useCallback(
    (e: React.MouseEvent<HTMLInputElement>): void => {
      const index = Number(e.currentTarget.dataset.index);

      setAutoFocusIndex(index);
    },
    []
  );

  const changeHandler = React.useCallback(
    (value: string, index: number): void => {
      if (!value) {
        setValues(
          values.map((v, currentIndex) => (currentIndex === index ? '' : v))
        );

        return;
      }

      const filledValues = value.split('');
      const newValues = values.map((v, currentIndex) => {
        if (currentIndex < index) {
          return v;
        }

        return filledValues[currentIndex - index] || v;
      });

      const nextIndex = Math.min(index + filledValues.length, codeLength - 1);
      const el =
        (refs[nextIndex] && refs[nextIndex].current) || refs[index].current;
      el.focus();

      setAutoFocusIndex(nextIndex);
      setValues(newValues);
    },
    [refs, values]
  );

  const onFocus = React.useCallback((e: React.FocusEvent<HTMLInputElement>) => {
    e.currentTarget.select();
  }, []);

  const onChange = React.useCallback(
    (e: React.ChangeEvent<HTMLInputElement>): void => {
      const value = e.target.value;
      const index = Number(e.target.dataset.index);

      changeHandler(value, index);
    },
    [changeHandler]
  );

  const onKeyDown = React.useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>): void => {
      const keyCode = e.keyCode;
      const i = Number(e.currentTarget.dataset.index);
      const prevIndex = i - 1;
      const nextIndex = i + 1;
      const currentInput = refs[i] && refs[i].current;
      const prevInput = refs[prevIndex] ? refs[prevIndex].current : null;
      const nextInput = refs[nextIndex] ? refs[nextIndex].current : null;

      if (!currentInput) {
        return;
      }

      const KEY_CODE: Record<string, number> = {
        backspace: 8,
        left: 37,
        right: 39,
      };

      switch (keyCode) {
        case KEY_CODE.left: {
          e.preventDefault();
          if (prevInput) {
            prevInput.focus();
          }
          break;
        }
        case KEY_CODE.right: {
          e.preventDefault();
          if (nextInput) {
            nextInput.focus();
          }
          break;
        }
        case KEY_CODE.backspace: {
          e.preventDefault();
          if (currentInput.value) {
            changeHandler('', i);
          } else if (prevInput) {
            prevInput.focus();
            changeHandler('', prevIndex);
          }
          break;
        }
        default: {
          break;
        }
      }
    },
    [refs, changeHandler]
  );

  return (
    <div className={className}>
      <div className={styles.codeWrapper}>
        {refs.map((ref, i) => (
          <Input
            key={i}
            inputRef={ref}
            className={styles.codeInput}
            value={values[i]}
            autoFocus={autoFocusIndex === i}
            onClick={onInputClick}
            onInput={onChange}
            onKeyDown={onKeyDown}
            onFocus={onFocus}
            data-index={i}
          />
        ))}
      </div>
      <Error show={isFilled && isIncorrectCode} className="margin1">
        <Trans i18nKey="importEmail.incorrectCode" />
      </Error>
      {isPending && (
        <Button className="center fullwidth" type="transparent" loading />
      )}
    </div>
  );
};
