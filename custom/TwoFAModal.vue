<template>
    <div class="af-two-factors-modal fixed inset-0 z-[9999] flex items-center justify-center bg-black/50 top-0 bottom-0 left-0 right-0"
    v-show ="modelShow && (isLoading === false)">
      <div v-if="modalMode === 'totp'" class="af-two-factor-modal-totp flex flex-col items-center relative bg-white dark:bg-gray-700 rounded-lg shadow p-6 w-full max-w-md">
        <div id="mfaCode-label" class="mb-4 text-gray-700 dark:text-gray-100 text-center">
          <p> {{ customDialogTitle }} </p>
          <p>{{ $t('Please enter your authenticator code') }}</p>
        </div>
        
        <div class="flex flex-col max-w-[calc(15rem_+_60px)]">
          <div class="mb-4 w-full flex justify-center" ref="otpRoot">
            <v-otp-input
              ref="confirmationResult"
              container-class="grid grid-cols-6 gap-3 w-full"
              input-classes="bg-gray-50 text-center flex justify-center otp-input border leading-none border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-10 h-10 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
              :num-inputs="6"
              inputType="number"
              inputmode="numeric"
              :should-auto-focus="true"
              :should-focus-order="true"
              v-model:value="bindValue"
              @on-complete="handleOnComplete"
            />
          </div>
    
          <div class="flex justify-between items-center gap-32 w-full">
            <p v-if="doesUserHavePasskeys===true" class="underline hover:no-underline text-lightPrimary whitespace-nowrap hover:cursor-pointer" @click="modalMode = 'passkey'" >{{$t('use passkey')}}</p>
            <Button
              class="px-4 py-2 rounded border"
              @click="onCancel"
              :disabled="inProgress"
            >{{ $t('Cancel') }}</Button>
          </div>
        </div>
      </div>



      <div v-else-if="modalMode === 'passkey'" class="af-two-factor-modal-passkeys flex flex-col items-center justify-center py-4 gap-6 relative bg-white dark:bg-gray-700 rounded-lg shadow p-6">
        <button
          type="button"
          class="text-lightDialogCloseButton bg-transparent hover:bg-lightDialogCloseButtonHoverBackground hover:text-lightDialogCloseButtonHover rounded-lg text-sm w-8 h-8 ms-auto inline-flex justify-center items-center dark:text-darkDialogCloseButton dark:hover:bg-darkDialogCloseButtonHoverBackground dark:hover:text-darkDialogCloseButtonHover"
          @click="onCancel"
        >
          <svg class="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
            <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
          </svg>
          <span class="sr-only">{{$t('Close modal')}}</span>
        </button>
        <IconShieldOutline class="af-2fa-shield-icon w-16 h-16 text-lightPrimary dark:text-darkPrimary"/>
        <p class="text-4xl font-semibold mb-4 text:gray-900 dark:text-gray-200 ">{{$t('Passkey')}}</p>
        <div class="mb-2 max-w-[300px] text:gray-900 dark:text-gray-200">
          <p class="mb-2">{{customDialogTitle}} </p>
          <p>{{$t('Authenticate yourself using the button below')}}</p>
        </div>
        <Button @click="usePasskeyButtonClick" :disabled="isFetchingPasskey" :loader="isFetchingPasskey" class="w-full mx-16">
          {{$t('Use passkey')}}
        </Button>
        <div v-if="modalMode === 'passkey'" class="af-2fa-passkey-issues-card  max-w-sm px-6 pt-3 w-full bg-white border border-gray-200 rounded-lg shadow-sm dark:bg-gray-800 dark:border-gray-700">
          <div class="mb-3 font-normal text-gray-700 dark:text-gray-400">
            <p>{{$t('Have issues with passkey?')}}</p>
            <p class="underline hover:no-underline text-lightPrimary whitespace-nowrap hover:cursor-pointer" @click="modalMode = 'totp'" >{{$t('use TOTP')}}</p>
          </div>
        </div>



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
  import adminforth from '@/adminforth';


  declare global {
    interface Window {
      adminforthTwoFaModal: {
        get2FaConfirmationResult: (        
          verifyingCallback?: (confirmationResult: string) => Promise<boolean>,
          title?: string
        ) => Promise<any>;
      };
    }
  }
  const props = defineProps<{
    autoFinishLogin?: boolean
  }>();
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
    get2FaConfirmationResult: (verifyingCallback?: (confirmationResult: string) => Promise<boolean>, title?: string) =>
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