import { ref } from 'vue';
import { defineStore } from 'pinia';

export type TwoFaConfirmationResult =
  | { mode: 'totp'; result: string }
  | { mode: 'passkey'; result: Record<string, any> };

type VerifyFn = (confirmationResult: string) => Promise<boolean> | boolean;
type Get2FaConfirmationResultHandler = (
  title?: string,
  verifyingCallback?: VerifyFn
) => Promise<TwoFaConfirmationResult>;

declare global {
  interface Window {
    adminforthTwoFaModal: {
      get2FaConfirmationResult: Get2FaConfirmationResultHandler;
    };
  }
}

export const useTwoFactorsAuthApi = defineStore('twoFactorsAuthApi', () => {
  const get2FaConfirmationResultHandler = ref<Get2FaConfirmationResultHandler | null>(null);

  function setGet2FaConfirmationResultHandler(handler: Get2FaConfirmationResultHandler | null) {
    get2FaConfirmationResultHandler.value = handler;
  }

  async function get2FaConfirmationResult(
    title?: string,
    verifyingCallback?: VerifyFn
  ): Promise<TwoFaConfirmationResult> {
    if (!get2FaConfirmationResultHandler.value) {
      throw new Error('Two factors auth modal API is not initialized');
    }
    return get2FaConfirmationResultHandler.value(title, verifyingCallback);
  }

  function initGlobalApi() {
    window.adminforthTwoFaModal = {
      get2FaConfirmationResult,
    };
  }

  return {
    get2FaConfirmationResult,
    setGet2FaConfirmationResultHandler,
    initGlobalApi,
  };
});

export const useTwoFactorsAuth = useTwoFactorsAuthApi;
