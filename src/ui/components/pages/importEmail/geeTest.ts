const w = window as any;

export const getGeeTestToken = (
  geetestUrl: string
): Promise<{
  geetest_challenge: string;
  geetest_seccode: string;
  geetest_validate: string;
}> => {
  return new Promise(async (res, rej) => {
    try {
      const response = await fetch(geetestUrl, {
        credentials: 'include',
      });
      const data = await response.json();

      if (!response.ok) {
        rej(data);
      }
      if (!w.initGeetest) {
        return rej();
      }

      w.initGeetest(
        {
          https: true,
          gt: data.gt,
          lang: 'en',
          hideSuccess: true,
          hideClose: false,
          challenge: data.challenge,
          offline: !data.success,
          new_captcha: true,
          product: 'bind',
          onError: rej,
        },
        function (geeTestObj: any) {
          if (!geeTestObj) {
            return rej();
          }
          geeTestObj.appendTo('body');
          geeTestObj.onReady(() => geeTestObj.verify());
          geeTestObj.onSuccess(() => res(geeTestObj.getValidate()));
          geeTestObj.onError(rej);
          geeTestObj.onClose(rej);
        },
        rej
      );
    } catch (e) {
      rej(e);
    }
  });
};
