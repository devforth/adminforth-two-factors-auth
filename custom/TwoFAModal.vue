<template>
    <div class="af-two-factors-modal fixed inset-0 z-[9999] flex items-center justify-center bg-black/50 top-0 bottom-0 left-0 right-0"
    v-show ="modelShow && (isLoading === false)">
      <div :class="`af-two-factor-modal-${modalMode}`" class="flex flex-col gap-4 relative bg-white dark:bg-gray-700 rounded-lg shadow p-6 w-full max-w-md">
        <div class="af-2fa-header flex flex-col items-center justify-center gap-3">
          <div class="af-2fa-icon-wrap w-14 h-14 shrink-0 flex items-center justify-center rounded-full bg-lightPrimary dark:bg-darkPrimary">
            <IconShieldOutline class="af-2fa-shield-icon w-7 h-7 text-white" />
          </div>
          <div id="mfaCode-label" class="af-2fa-title-wrap">
            <p class="af-2fa-title text-xl text-center font-medium text-gray-900 dark:text-white">{{ dialogTitle }}</p>
            <p class="af-2fa-subtitle text-xs text-center text-gray-500 dark:text-gray-400 mt-1">{{ subtitles[modalMode] }}</p>
          </div>
        </div>

        <pre v-if="dialogDetails" class="af-2fa-details max-h-60 overflow-auto rounded-lg bg-gray-100 p-3 text-xs text-gray-800 dark:bg-gray-900 dark:text-gray-100">{{ dialogDetails }}</pre>

        <ul v-if="confirmItems.length > 1" class="af-2fa-actions-list max-h-60 overflow-auto list-disc space-y-1 pl-5 text-sm text-gray-700 dark:text-gray-200">
          <li v-for="(item, i) in confirmItems" :key="i">{{ item }}</li>
        </ul>

        <template v-if="modalMode === 'totp'">
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
          <p v-if="codeError" class="af-2fa-code-error text-center text-xs text-red-600 dark:text-red-400">{{ codeError }}</p>
        </template>

        <div class="af-2fa-buttons flex gap-2">
          <Button variant="secondary" class="af-2fa-cancel-btn flex-1" @click="onCancel">{{ $t('Cancel') }}</Button>
          <Button v-if="modalMode === 'passkey'" @click="usePasskeyButtonClick" :disabled="isFetchingPasskey" :loader="isFetchingPasskey" class="af-2fa-passkey-btn flex-1 flex items-center justify-center gap-2">
            <IconShieldOutline class="w-4 h-4" />
            {{ $t('Use passkey') }}
          </Button>
          <Button v-else-if="modalMode === 'grace'" class="af-2fa-approve-btn flex-1" @click="approveInGracePeriod">{{ $t('Approve') }}</Button>
        </div>

        <p v-if="modalMode === 'totp' && doesUserHavePasskeys" class="af-2fa-totp-footer text-center text-xs text-gray-500 dark:text-gray-400">
          {{$t('Having trouble?')}}
          <button type="button" class="af-2fa-switch-to-passkey text-lightPrimary dark:text-white hover:underline cursor-pointer" @click="modalMode = 'passkey'">{{$t('Use passkey instead')}}</button>
        </p>
        <p v-else-if="modalMode === 'passkey'" class="af-2fa-passkey-footer text-center text-xs text-gray-500 dark:text-gray-400">
          {{$t('Having trouble?')}}
          <button type="button" class="af-2fa-switch-to-totp text-lightPrimary dark:text-white hover:underline cursor-pointer" @click="modalMode = 'totp'">{{$t('Use TOTP instead')}}</button>
        </p>
      </div>
    </div>
  </template>
  
  <script setup lang="ts">

  import VOtpInput from 'vue3-otp-input';
  import { ref, computed, nextTick, watch } from 'vue';
  import { useUserStore } from '@/stores/user';
  import { useI18n } from 'vue-i18n';
  import { callAdminForthApi } from '@/utils';
  import { Link, Button } from '@/afcl';
  import { IconShieldOutline } from '@iconify-prerendered/vue-flowbite';
  import { getPasskey } from './utils.js' 
  import { useAdminforth } from '@/adminforth';
  import websocket from '@/websocket';
  import { getAdminForthClientId } from '@/utils/clientId';
  import type { AdminUser } from '@/types/Common';
  import { useTwoFactorsAuthApi, type TwoFaConfirmationResult, type TwoFaDialogContent } from './use2faApi.js';
  const props = defineProps<{
    autoFinishLogin?: boolean
    adminUser?: AdminUser
  }>();

  const { alert } = useAdminforth();
  const twoFactorsAuthApi = useTwoFactorsAuthApi();

  type AutoVerifySession = { sessionId: string; actionDescription?: string };

  const isAwaiting2FAResult = ref(false);
  let allowAddNewSessions = true;
  const ALLOW_NEW_SESSIONS_PERIOD = 1000;
  const MAX_ACTIONS_PER_CONFIRMATION = 20;
  const sessionsToResolve = ref<AutoVerifySession[]>([]);
  // Sessions over the limit of one confirmation wait for the next one, so the user never confirms an action they did not see.
  let queuedSessions: AutoVerifySession[] = [];

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
  
  watch(props, () => {
    if (props.adminUser) {
      websocket.unsubscribeByPrefix(`/user2fa/`);
      const user2FaTopic = `/user2fa/${props.adminUser.pk}/${getAdminForthClientId()}`;
      websocket.subscribe(user2FaTopic, async (session: AutoVerifySession) => {
        if (!allowAddNewSessions) {
          alert({message: t('Some process or user tries to add new actions to confirm. Action was blocked'), variant: 'warning'});
          return;
        }
        if (sessionsToResolve.value.length < MAX_ACTIONS_PER_CONFIRMATION) {
          sessionsToResolve.value.push(session);
        } else {
          queuedSessions.push(session);
        }
        if (isAwaiting2FAResult.value) {
          return;
        }
        while (sessionsToResolve.value.length) {
          await confirmSessions();
          sessionsToResolve.value = queuedSessions.splice(0, MAX_ACTIONS_PER_CONFIRMATION);
        }
        allowAddNewSessions = true;
      });
      websocket.subscribe(`${user2FaTopic}/resolve`, async (data: {sessionId: string}) => {
        queuedSessions = queuedSessions.filter((session) => session.sessionId !== data.sessionId);
        if (sessionsToResolve.value.some((session) => session.sessionId === data.sessionId) && rejectFn && modelShow.value) {
          onCancel();
          sessionsToResolve.value = sessionsToResolve.value.filter((session) => session.sessionId !== data.sessionId);
        }
      });
    }
  }, { immediate: true });


  async function confirmSessions() {
    let confirmationResult;
    try {
      isAwaiting2FAResult.value = true;
      confirmationResult = await twoFactorsAuthApi.get2FaConfirmationResult(sessionsToResolve.value[0].actionDescription);
    } catch (error) {
      if (!isTwoFaCancel(error)) {
        console.error('[AdminForth 2FA] Error during 2FA confirmation', error);
      }
    }
    isAwaiting2FAResult.value = false;
    try {
      const response = await callAdminForthApi({
        method: "POST",
        path: "/plugin/passkeys/resolveVerifyAuto",
        body: { confirmationResult, sessionsIds: sessionsToResolve.value.map((session) => session.sessionId) }
      });
      if (!response.ok && response.code === 'VERIFICATION_CANCELLED'){
        alert({message: t('Verification session finished or cancelled.'), variant: 'warning'});
      } else if (!response.ok) {
        alert({message: response.error || t('Verification failed'), variant: 'danger'}); 
      }
    } catch (error) {
      console.error('Error resolving automatic 2FA verification:', error);
    }
  }

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
  let verifyFn: null | ((confirmationResult: string) => Promise<boolean> | boolean) = null;
  let rejectFn: ((err?: any) => void) | null = null;

  function isTwoFaCancel(error: unknown) {
    return error === 'Cancel';
  }


  function get2FaConfirmationResult(
    title?: string,
    verifyingCallback?: (confirmationResult: string) => Promise<boolean> | boolean,
    { details, items }: TwoFaDialogContent = {},
  ): Promise<TwoFaConfirmationResult> {
    return new Promise((resolve, reject) => {
      (async () => {
        if (modelShow.value) {
          throw new Error(t('Modal is already open'));
        }
        const { skipAllowed, gracePeriod } = await checkIfSkipAllowModal();
        if (skipAllowed) {
          resolve({});
          return;
        }
        if (gracePeriod) {
          modalMode.value = 'grace';
        } else {
          await checkIfUserHasPasskeys();
        }
        customDialogTitle.value = title ?? '';
        dialogDetails.value = details ?? '';
        dialogItems.value = items ?? [];
        resolveFn = resolve;
        rejectFn = reject;
        verifyFn = verifyingCallback ?? null;
        modelShow.value = true;
        if (modalMode.value === 'totp') {
          await addEventListenerForOTPInput();
        }
      })().catch((error) => {
        if (!isTwoFaCancel(error)) {
          console.error('[AdminForth 2FA] Failed to open 2FA modal', error);
        }
        reject(error);
      });
    });
  }

  twoFactorsAuthApi.setGet2FaConfirmationResultHandler(get2FaConfirmationResult);
  twoFactorsAuthApi.initGlobalApi();
  
  const { t } = useI18n();
  const user = useUserStore();
  
  const confirmationResult = ref<any>(null);
  const otpRoot = ref<HTMLElement | null>(null);
  const bindValue = ref('');
  const doesUserHavePasskeys = ref(false);
  const modalMode = ref<"totp" | "passkey" | "grace">("totp");
  const isLoading = ref(false);
  const isFetchingPasskey = ref(false);
  const customDialogTitle = ref("");
  const dialogDetails = ref("");
  const dialogItems = ref<string[]>([]);
  // verifyAuto calls that arrive together are confirmed with one code.
  const confirmItems = computed(() => sessionsToResolve.value.length > 1
    ? sessionsToResolve.value.map((session) => session.actionDescription ?? t('Action without a description'))
    : dialogItems.value);
  const dialogTitle = computed(() => confirmItems.value.length > 1
    ? t('Confirm {count} actions', { count: confirmItems.value.length })
    : customDialogTitle.value || t("Confirm it's you"));
  const codeError = ref("");
  const subtitles = computed(() => ({
    totp: t('Please enter your authenticator code'),
    passkey: t('Confirm with your passkey'),
    grace: t('You verified recently, so no code is needed'),
  }));

  function approveInGracePeriod() {
    modelShow.value = false;
    resolveFn?.({});
  }

  async function usePasskeyButtonClick() {
    isFetchingPasskey.value = true;
    let passkeyData;
    try {
      passkeyData = await getPasskey();
    } catch (error) {
      onCancel();
      return null;
    } finally {
      isFetchingPasskey.value = false;
    }
    modelShow.value = false;
    const dataToReturn = {
      mode: "passkey",
      result: passkeyData
    }
    customDialogTitle.value = "";
    removeEventListenerForOTPInput();
    resolveFn?.(dataToReturn);
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
    if (!resolveFn) throw new Error(t('Modal is not initialized properly'));
    let checked: { error: string } | { result: TwoFaConfirmationResult };
    try {
      checked = await checkCode(value);
    } catch (err) {
      rejectFn?.(err);
      return;
    }
    if ('error' in checked) {
      codeError.value = checked.error;
      bindValue.value = '';
      confirmationResult.value?.clearInput();
      return;
    }

    modelShow.value = false;
    codeError.value = "";
    customDialogTitle.value = "";
    removeEventListenerForOTPInput();
    resolveFn(checked.result);
  }
  
  
  async function checkCode(code: string): Promise<{ error: string } | { result: TwoFaConfirmationResult }> {
    if (verifyFn) {
      return (await verifyFn(code)) ? { result: { mode: 'totp', result: code } } : { error: t('Wrong or expired OTP code') };
    }
    const response = await callAdminForthApi({ method: 'POST', path: '/plugin/twofa/verify', body: { code } });
    return response?.ok
      ? { result: { mode: 'verifiedTotp', result: response.verifiedCodeToken } }
      : { error: response?.error ?? t('Wrong or expired OTP code') };
  }

  function onCancel() {
    modelShow.value = false;
    codeError.value = "";
    bindValue.value = '';
    confirmationResult.value?.clearInput();
    removeEventListenerForOTPInput();
    rejectFn?.("Cancel");
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
      
      doesUserHavePasskeys.value = Boolean(response.ok && response.data.length);
      modalMode.value = doesUserHavePasskeys.value ? "passkey" : "totp";
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

  function handleGlobalFocusIn(event: FocusEvent) {
    const inputs = getOtpInputs();
    if (!inputs.length) return;
    const target = event.target as Element | null;
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


  async function checkIfSkipAllowModal(): Promise<{ skipAllowed: boolean; gracePeriod?: boolean }> {
    try {
      return await callAdminForthApi({
        method: "GET",
        path: "/plugin/twofa/skip-allow-modal",
      });
    } catch (error) {
      console.error('Error checking skip allow modal:', error);
      return { skipAllowed: false };
    }
  }

</script>
  
<style scoped>
  :deep(.otp-input-container) {
    display: flex;
    gap: 0.75rem;
  }
</style>
