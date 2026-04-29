<template>
    <div class="af-two-factors-modal fixed inset-0 z-[9999] flex items-center justify-center bg-black/50 top-0 bottom-0 left-0 right-0"
    v-show ="modelShow && (isLoading === false)">
      <div v-if="modalMode === 'totp'" class="af-two-factor-modal-totp flex flex-col gap-4 relative bg-white dark:bg-gray-700 rounded-lg shadow p-6 w-full max-w-md">
        <button
          type="button"
          class="af-2fa-close-btn text-lightDialogCloseButton bg-transparent hover:bg-lightDialogCloseButtonHoverBackground hover:text-lightDialogCloseButtonHover rounded-lg text-sm w-8 h-8 ms-auto inline-flex justify-center items-center dark:text-darkDialogCloseButton dark:hover:bg-darkDialogCloseButtonHoverBackground dark:hover:text-darkDialogCloseButtonHover"
          @click="onCancel"
        >
          <svg class="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
            <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
          </svg>
          <span class="sr-only">{{$t('Close modal')}}</span>
        </button>

        <div class="af-2fa-totp-header flex flex-col items-center justify-center gap-3">
          <div class="af-2fa-icon-wrap w-14 h-14 shrink-0 flex items-center justify-center rounded-full bg-lightPrimary dark:bg-darkPrimary">
            <IconShieldOutline class="af-2fa-shield-icon w-7 h-7 text-white" />
          </div>
          <div id="mfaCode-label" class="af-2fa-totp-title-wrap">
            <p v-if="customDialogTitle" class="af-2fa-custom-title text-xl text-center font-medium text-gray-900 dark:text-white">{{ customDialogTitle }}</p>
            <p class="af-2fa-totp-subtitle text-xs text-center text-gray-500 dark:text-gray-400 mt-1">{{ $t('Please enter your authenticator code') }}</p>
          </div>
        </div>

        <div class="af-2fa-otp-root flex justify-center" ref="otpRoot">
          <v-otp-input
            ref="confirmationResult"
            container-class="grid grid-cols-6 gap-3"
            input-classes="bg-gray-50 text-center flex justify-center otp-input border leading-none border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-10 h-10 dark:bg-gray-600 dark:border-gray-500 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
            :num-inputs="6"
            inputType="number"
            inputmode="numeric"
            :should-auto-focus="true"
            :should-focus-order="true"
            v-model:value="bindValue"
            @on-complete="handleOnComplete"
          />
        </div>
        <p v-if="doesUserHavePasskeys" class="af-2fa-totp-footer text-center text-xs text-gray-500 dark:text-gray-400">
          {{$t('Having trouble?')}}
          <button type="button" class="af-2fa-switch-to-passkey text-lightPrimary dark:text-white hover:underline cursor-pointer" @click="modalMode = 'passkey'">{{$t('Use passkey instead')}}</button>
        </p>
        <p class="af-2fa-multiple-actions text-center text-red-500 text-xs" v-if="sessionsIdsToResolve.length > 1"> You are confirming {{ sessionsIdsToResolve.length }} actions</p>
      </div>

      <div v-else-if="modalMode === 'passkey'" class="af-two-factor-modal-passkeys flex flex-col gap-4 relative bg-white dark:bg-gray-700 rounded-lg shadow p-6 w-full max-w-md">
        <button
          type="button"
          class="af-2fa-close-btn text-lightDialogCloseButton bg-transparent hover:bg-lightDialogCloseButtonHoverBackground hover:text-lightDialogCloseButtonHover rounded-lg text-sm w-8 h-8 ms-auto inline-flex justify-center items-center dark:text-darkDialogCloseButton dark:hover:bg-darkDialogCloseButtonHoverBackground dark:hover:text-darkDialogCloseButtonHover"
          @click="onCancel"
        >
          <svg class="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
            <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
          </svg>
          <span class="sr-only">{{$t('Close modal')}}</span>
        </button>

        <div class="af-2fa-passkey-header flex flex-col items-center justify-center gap-3">
          <div class="af-2fa-icon-wrap w-14 h-14 shrink-0 flex items-center justify-center rounded-full bg-lightPrimary dark:bg-darkPrimary">
            <IconShieldOutline class="af-2fa-shield-icon w-7 h-7 text-white" />
          </div>
          <div class="af-2fa-passkey-title-wrap">
            <p class="af-2fa-passkey-title text-xl text-center font-medium text-gray-900 dark:text-white">{{$t('Verify to add passkey')}}</p>
            <p class="af-2fa-passkey-subtitle text-xs text-center text-gray-500 dark:text-gray-400 mt-1">{{$t("Confirm it's you before registering a new passkey on this device.")}}</p>
          </div>
        </div>

        <div class="af-2fa-passkey-steps flex flex-col gap-2 mt-2">
          <div
            v-for="(step, i) in [
              $t('Click the button below to begin'),
              $t('Authenticate with your device biometrics or PIN'),
              $t('Your passkey will be saved automatically'),
            ]"
            :key="i"
            class="af-2fa-passkey-step flex items-center gap-2.5 px-3 py-2 rounded-lg bg-gray-50 dark:bg-gray-600/50 text-xs text-gray-600 dark:text-gray-300"
          >
            <span class="af-2fa-step-number shrink-0 w-5 h-5 flex items-center justify-center rounded-full bg-lightPrimary dark:bg-darkPrimary text-white font-semibold text-xs">{{ i + 1 }}</span>
            {{ step }}
          </div>
        </div>

        <Button @click="usePasskeyButtonClick" :disabled="isFetchingPasskey" :loader="isFetchingPasskey" class="af-2fa-passkey-btn w-full flex items-center justify-center gap-2 mt-2">
          <IconShieldOutline class="w-4 h-4" />
          {{$t('Use passkey to verify')}}
        </Button>
        <p class="af-2fa-passkey-footer text-center text-xs text-gray-500 dark:text-gray-400">
          {{$t('Having trouble?')}}
          <button type="button" class="af-2fa-switch-to-totp text-lightPrimary dark:text-white hover:underline cursor-pointer" @click="modalMode = 'totp'">{{$t('Use TOTP instead')}}</button>
        </p>
        <p class="af-2fa-multiple-actions text-center text-red-500 text-xs" v-if="sessionsIdsToResolve.length > 1"> You are confirming {{ sessionsIdsToResolve.length }} actions</p>
      </div>
    </div>
  </template>
  
  <script setup lang="ts">

  import VOtpInput from 'vue3-otp-input';
  import { ref, nextTick, watch, onMounted } from 'vue';
  import { useUserStore } from '@/stores/user';
  import { useI18n } from 'vue-i18n';
  import { callAdminForthApi } from '@/utils';
  import { Link, Button } from '@/afcl';
  import { IconShieldOutline } from '@iconify-prerendered/vue-flowbite';
  import { getPasskey } from './utils.js' 
  import { useAdminforth } from '@/adminforth';
  import websocket from '@/websocket';
  import type { AdminUser } from '@/types/Common';

  type TwoFaConfirmationResult = { mode: 'totp'; result: string } | { mode: 'passkey'; result: Record<string, any> };

  declare global {
    interface Window {
      adminforthTwoFaModal: {
        get2FaConfirmationResult: (
          title?: string,
          verifyingCallback?: (confirmationResult: string) => Promise<boolean>
        ) => Promise<TwoFaConfirmationResult>;
      };
    }
  }
  const props = defineProps<{
    autoFinishLogin?: boolean
    adminUser?: AdminUser
  }>();

  const { alert } = useAdminforth();

  const isAwaiting2FAResult = ref(false);
  let allowAddNewSessions = true;
  const ALLOW_NEW_SESSIONS_PERIOD = 1000;
  const sessionsIdsToResolve = ref<string[]>([]);

  watch(isAwaiting2FAResult, (awaiting) => {
    if (awaiting) {
      allowAddNewSessions = true;
      setTimeout(() => {
        if (isAwaiting2FAResult.value) {
          allowAddNewSessions = false;
        }
      }, ALLOW_NEW_SESSIONS_PERIOD);
    }
  });
  
  watch( props, () => {
    if (props.adminUser) {
      websocket.unsubscribeByPrefix(`/user2fa/`);
      websocket.subscribe(`/user2fa/${props.adminUser.pk}`, async (data: {sessionId: string}) => {
        if (!allowAddNewSessions) {
          alert({message: 'Some process or user tries to add new actions to confirm. Action was blocked', variant: 'warning'});
          return;
        }
        sessionsIdsToResolve.value.push(data.sessionId);
        let confirmationResult;
        if (isAwaiting2FAResult.value) {
          return;
        }
        try {
          isAwaiting2FAResult.value = true;
          confirmationResult = await window.adminforthTwoFaModal.get2FaConfirmationResult();
        } catch (error) {
          console.error('Error during 2FA confirmation:', error);
        }
        isAwaiting2FAResult.value = false;
        try {
          const response = await callAdminForthApi({
            method: "POST",
            path: "/plugin/passkeys/resolveVerifyAuto",
            body: { confirmationResult, sessionsIds: sessionsIdsToResolve.value }
          });
          if (!response.ok && response.error === 'No session ID or confirmation result'){
            alert({message: 'Verification session finished or cancelled.', variant: 'warning'});
          } else if (!response.ok) {
            alert({message: 'Verification failed', variant: 'danger'});
          } else if (response.ok) {
            alert({message: 'Verification successful', variant: 'success'});
          }
          sessionsIdsToResolve.value = [];
        } catch (error) {
          console.error('Error resolving automatic 2FA verification:', error);
        }
        allowAddNewSessions = true;
      });
      websocket.subscribe(`/user2fa/${props.adminUser.pk}-resolve`, async (data: {sessionId: string}) => {
        if (sessionsIdsToResolve.value.includes(data.sessionId) && rejectFn && modelShow.value) {
          onCancel();
          sessionsIdsToResolve.value = sessionsIdsToResolve.value.filter(id => id !== data.sessionId);
        }
      });
    }
  })


  const emit = defineEmits<{
    (e: 'resolved', payload: any): void
    (e: 'rejected', err?: any): void
    (e: 'closed'): void
  }>();

  async function addEventListenerForOTPInput(){
    document.addEventListener('focusin', handleGlobalFocusIn, true);
    focusFirstAvailableOtpInput();
    isLoading.value = false;
    await nextTick();
    const rootEl = otpRoot.value;
    rootEl && rootEl.addEventListener('focusout', handleFocusOut, true);
  }

  function removeEventListenerForOTPInput() {
    window.removeEventListener('paste', handlePaste);
    document.removeEventListener('focusin', handleGlobalFocusIn, true);
    const rootEl = otpRoot.value;
    rootEl && rootEl.removeEventListener('focusout', handleFocusOut, true);
    // Abort any in-flight WebAuthn request when leaving the component
  }


  const modelShow = ref(false);
  let resolveFn: ((confirmationResult: any) => void) | null = null;
  let verifyingCallback: ((confirmationResult: string) => boolean) | null = null;
  let verifyFn: null | ((confirmationResult: string) => Promise<boolean> | boolean) = null;
  let rejectFn: ((err?: any) => void) | null = null;


  window.adminforthTwoFaModal = {
    get2FaConfirmationResult: (title?: string, verifyingCallback?: (confirmationResult: string) => Promise<boolean>) =>
      new Promise(async (resolve, reject) => {
      if (modelShow.value) throw new Error('Modal is already open');
      const skipAllowModal = await checkIfSkipAllowModal();
      if (skipAllowModal) {
        resolve({ code: "123456" }); // dummy code
        return;
      }
      await checkIfUserHasPasskeys();
      if (title) {
        customDialogTitle.value = title;
      }
      modelShow.value = true;
      if (modalMode.value === 'totp') {
        await addEventListenerForOTPInput();
      }
      resolveFn = resolve;
      rejectFn = reject;
      verifyFn = verifyingCallback ?? null;
    }),
  };
  
  const { t } = useI18n();
  const user = useUserStore();
  
  const confirmationResult = ref<any>(null);
  const otpRoot = ref<HTMLElement | null>(null);
  const bindValue = ref('');
  const doesUserHavePasskeys = ref(false);
  const modalMode = ref<"totp" | "passkey">("totp");
  const isLoading = ref(false);
  const customDialogTitle = ref("");
  
  async function usePasskeyButtonClick() {
    let passkeyData;
    try {
      passkeyData = await getPasskey();
    } catch (error) {
      onCancel();
      return null;
    }
    modelShow.value = false;
    const dataToReturn = {
      mode: "passkey",
      result: passkeyData
    }
    customDialogTitle.value = "";
    removeEventListenerForOTPInput();
    resolveFn(dataToReturn);
  }

  function tagOtpInputs() {
    const root = otpRoot.value;
    if (!root) return;
    const inputs = root.querySelectorAll('input.otp-input');
    inputs.forEach((el, idx) => {
      el.setAttribute('name', 'mfaCode');
      el.setAttribute('id', `mfaCode-${idx + 1}`);
      el.setAttribute('autocomplete', 'one-time-code');
      el.setAttribute('inputmode', 'numeric');
      el.setAttribute('aria-labelledby', 'mfaCode-label');
    });
    (inputs[0] as HTMLInputElement)?.focus();

  }
  
  function handlePaste(event: ClipboardEvent) {
    event.preventDefault();
    const pastedText = event.clipboardData?.getData('text') || '';
    if (pastedText.length === 6) {
      confirmationResult.value?.fillInput(pastedText);
    }
  }
  
  async function handleOnComplete(value: string) {
    await sendConfirmationResult(value);
  }
  
  async function sendConfirmationResult(value: string) {
    if (!resolveFn) throw new Error('Modal is not initialized properly');
    if (verifyFn) {
      try {
        const ok = await verifyFn(value);
        if (!ok) {
          rejectFn?.(new Error('Invalid code'));
          return;
        }
      } catch (err) {
        rejectFn?.(err);
        return;
      }
    }

    modelShow.value = false;
    const dataToReturn = {
      mode: "totp",
      result: value
    }
    customDialogTitle.value = "";
    removeEventListenerForOTPInput();
    resolveFn(dataToReturn);
  }
  
  
  function onCancel() {
    modelShow.value = false;
    bindValue.value = '';
    confirmationResult.value?.clearInput();
    removeEventListenerForOTPInput();
    rejectFn("Cancel");
    emit('rejected', new Error('cancelled'));
    emit('closed');
  }

  watch(modalMode, async (newMode) => {
    if (newMode === 'totp') {
      await addEventListenerForOTPInput();
    } else {
      removeEventListenerForOTPInput();
    }
  });

  watch(modelShow, async (open) => {
  if (open) {
    await nextTick();
    const htmlRef = document.querySelector('html');
    if (htmlRef) {
      htmlRef.style.overflow = 'hidden';
    }
    
    // Wait for conditional rendering to complete
    if (modalMode.value === 'totp' && !isLoading.value) {
      await nextTick();
      setTimeout(() => {
        tagOtpInputs();
        window.addEventListener('paste', handlePaste);
      }, 100);
    } else {
      window.addEventListener('paste', handlePaste);
    }
  } else {
    window.removeEventListener('paste', handlePaste);
    const htmlRef = document.querySelector('html');
    if (htmlRef) {
      htmlRef.style.overflow = '';
    }
    bindValue.value = '';
    confirmationResult.value?.clearInput();
  }
});

  async function checkIfUserHasPasskeys() {
    isLoading.value = true;
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
      // Fallback to TOTP if there's an error
      doesUserHavePasskeys.value = false;
      modalMode.value = "totp";
    } finally {
      isLoading.value = false;
    }
  }

  function getOtpInputs() {
    const root = otpRoot.value;
    if (!root) return [];
    return Array.from(root.querySelectorAll('input.otp-input'));
  }

  function focusFirstAvailableOtpInput() {
    const inputs = getOtpInputs();
    if (!inputs.length) {
      // Retry after a short delay if inputs aren't ready yet
      setTimeout(() => focusFirstAvailableOtpInput(), 50);
      return;
    }
    const firstEmpty = inputs.find((i) => !(i as HTMLInputElement).value);
    ((firstEmpty || inputs[0]) as HTMLInputElement).focus();
  }

  function handleGlobalFocusIn(event) {
    const inputs = getOtpInputs();
    if (!inputs.length) return;
    const target = event.target;
    if (!target) return;
    if (!inputs.includes(target)) {
      requestAnimationFrame(() => {
        focusFirstAvailableOtpInput();
      });
    }
  }

  function handleFocusOut() {
    requestAnimationFrame(() => {
      const inputs = getOtpInputs();
      if (!inputs.length) return;
      const active = document.activeElement;
      if (!active || !inputs.includes(active)) {
        focusFirstAvailableOtpInput();
      }
    });
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

</script>
  
<style scoped>
  :deep(.otp-input-container) {
    display: flex;
    gap: 0.75rem;
  }
</style>