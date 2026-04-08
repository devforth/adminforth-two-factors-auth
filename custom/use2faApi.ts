import { ref } from 'vue';
import { defineStore } from 'pinia'
import { callAdminForthApi } from '@/utils/utils';

export const use2faApi = defineStore('2fa', () => {
  const isOpened = ref(false);
  const customDialogTitle = ref('');
  const resolveFn = ref<((confirmationResult: any) => void) | null>(null);
  const verifyFn = ref<null | ((confirmationResult: string) => Promise<boolean> | boolean)>(null);
  const rejectFn = ref<((err?: any) => void) | null>(null);
  const addEventListenerForOTPInput = ref<null | (() => Promise<void>)>(null);
  const doesUserHavePasskeys = ref(false);
  const modalMode = ref<"totp" | "passkey">("totp");

  function setModalMode(mode: "totp" | "passkey") {
    modalMode.value = mode;
  }
  
  function registerAddEventListenerForOTPInput(fn: () => Promise<void>) {
    addEventListenerForOTPInput.value = fn;
  }
  
  function setCustomDialogTitle(title: string) {
    customDialogTitle.value = title;
  }

  async function checkIfSkipAllowModal(){
    try {
      const response = await callAdminForthApi({
        method: "GET",
        path: "/plugin/twofa/skip-allow-modal",
      });
      if ( response.skipAllowed === true ) {
        return true;
      } else {
        return false;
      }
    } catch (error) {
      console.error('Error checking skip allow modal:', error);
      return false;
    }
  }

  async function checkIfUserHasPasskeys() {
    try {
      const response = await callAdminForthApi({
        method: 'GET',
        path: '/plugin/passkeys/getPasskeys',
      });
      
      if (response.ok) {
        if (response.data.length >= 1) {
          doesUserHavePasskeys.value = true;
          modalMode.value = "passkey";
        } else {
          doesUserHavePasskeys.value = false;
          modalMode.value = "totp";
        }
      }
    } catch (error) {
      console.error('Error checking passkeys:', error);
      doesUserHavePasskeys.value = false;
      modalMode.value = "totp";
      return false;
    }
  }

  function get2FaConfirmationResult(title?: string, verifyingCallback?: (confirmationResult: string) => Promise<boolean> | boolean) {
    return new Promise(async (resolve, reject) => {
      if (isOpened.value) throw new Error('Modal is already open');
      const skipAllowModal = await checkIfSkipAllowModal();
      if (skipAllowModal) {
        resolve({ code: "123456" }); // dummy code
        return;
      }
      await checkIfUserHasPasskeys();
      if (title) {
        customDialogTitle.value = title;
      }
      isOpened.value = true;
      if (!doesUserHavePasskeys.value && addEventListenerForOTPInput.value && typeof addEventListenerForOTPInput.value === 'function') {
        await addEventListenerForOTPInput.value();
      }
      resolveFn.value = resolve;
      rejectFn.value = reject;
      verifyFn.value = verifyingCallback ?? null;
    });
  }

  function setIsOpened(value: boolean) {
    isOpened.value = value;
  }

  return {
    isOpened,
    customDialogTitle,
    get2FaConfirmationResult,
    setIsOpened,
    setCustomDialogTitle,
    registerAddEventListenerForOTPInput,
    resolveFn,
    verifyFn,
    rejectFn,
    setModalMode,
    doesUserHavePasskeys,
    modalMode,
  };
});