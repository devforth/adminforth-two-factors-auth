<template>
    <div class="af-two-factors-modal fixed inset-0 z-[9999] flex items-center justify-center bg-black/50 top-0 bottom-0 left-0 right-0 px-4"
    v-show ="modelShow && (isLoading === false)">
      <div :class="`af-two-factor-modal-${modalMode}`" class="relative flex flex-col w-full max-w-[460px] overflow-hidden rounded-xl border border-lightDialogBreakLine bg-lightDialogBackgorund shadow-2xl dark:border-darkDialogBreakLine dark:bg-darkDialogBackgorund">
        <div class="af-2fa-header flex items-start gap-3.5 border-b border-lightDialogBreakLine py-5 pl-6 pr-4 dark:border-darkDialogBreakLine">
          <div class="af-2fa-icon-wrap flex w-10 h-10 shrink-0 items-center justify-center rounded-[10px] bg-lightPrimary/10 text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">
            <IconShieldCheckOutline class="af-2fa-shield-icon w-6 h-6" />
          </div>
          <div class="af-2fa-title-wrap flex-1 min-w-0">
            <p class="af-2fa-title text-[17px] leading-6 font-semibold text-lightDialogHeaderText dark:text-darkDialogHeaderText">{{ dialogTitle }}</p>
            <p class="af-2fa-subtitle mt-0.5 text-[13px] leading-[18px] text-gray-500 dark:text-gray-400">{{ subtitles[modalMode] }}</p>
          </div>
          <button type="button" :aria-label="$t('Cancel')" class="af-2fa-close-btn -mt-1 inline-flex w-9 h-9 shrink-0 items-center justify-center rounded-lg text-lightDialogCloseButton hover:bg-lightDialogCloseButtonHoverBackground hover:text-lightDialogCloseButtonHover dark:text-darkDialogCloseButton dark:hover:bg-darkDialogCloseButtonHoverBackground dark:hover:text-darkDialogCloseButtonHover" @click="onCancel">
            <IconCloseOutline class="w-5 h-5" />
          </button>
        </div>

        <div class="af-2fa-body flex flex-col gap-5 px-6 pt-5 pb-6">
          <pre v-if="dialogDetails" class="af-2fa-details max-h-60 overflow-auto rounded-[10px] border border-lightDialogBreakLine bg-gray-50 p-3 text-xs text-gray-800 dark:border-darkDialogBreakLine dark:bg-gray-800 dark:text-gray-100">{{ dialogDetails }}</pre>

          <div v-if="confirmItems.length" class="af-2fa-actions">
            <p class="mb-2 text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ $t('You are approving') }}</p>
            <ul class="af-2fa-actions-list max-h-60 overflow-auto divide-y divide-lightDialogBreakLine rounded-[10px] border border-lightDialogBreakLine bg-gray-50 dark:divide-darkDialogBreakLine dark:border-darkDialogBreakLine dark:bg-gray-800">
              <li v-for="(item, i) in confirmItems" :key="i" class="flex gap-3 px-3.5 py-3">
                <span aria-hidden="true" class="mt-2 w-1.5 h-1.5 shrink-0 rounded-full bg-lightPrimary dark:bg-darkPrimary"></span>
                <span class="text-[15px] leading-[22px] break-words text-gray-800 dark:text-gray-100">{{ item }}</span>
              </li>
            </ul>
          </div>

          <div v-if="modalMode === 'totp'">
            <p id="mfaCode-label" class="mb-2 text-[13px] font-medium text-gray-700 dark:text-gray-300">{{ $t('Authenticator code') }}</p>
            <div class="af-2fa-otp-root text-gray-300 dark:text-gray-500" ref="otpRoot">
              <v-otp-input
                ref="confirmationResult"
                container-class="flex items-center gap-2"
                :input-classes="otpInputClasses"
                :num-inputs="6"
                inputType="number"
                inputmode="numeric"
                :should-auto-focus="true"
                :should-focus-order="true"
                v-model:value="bindValue"
                @on-complete="handleOnComplete"
              />
            </div>
            <p v-if="codeError" role="alert" class="af-2fa-code-error mt-2.5 flex items-center gap-1.5 text-[13px] text-red-600 dark:text-red-400">
              <IconExclamationCircleOutline class="w-4 h-4 shrink-0" />
              {{ codeError }}
            </p>
          </div>
          <div v-else-if="modalMode === 'passkey'" class="af-2fa-passkey-hint flex items-center gap-3.5 rounded-[10px] border border-lightDialogBreakLine bg-gray-50 px-4 py-3.5 dark:border-darkDialogBreakLine dark:bg-gray-800">
            <span class="flex w-11 h-11 shrink-0 items-center justify-center rounded-full bg-lightPrimary/10 text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">
              <IconFingerprintOutline class="w-6 h-6" />
            </span>
            <p class="text-[13px] leading-[19px] text-gray-500 dark:text-gray-400">{{ $t('Your browser will ask for Touch ID, Windows Hello or a security key.') }}</p>
          </div>
          <p v-else role="status" class="af-2fa-grace-notice flex items-start gap-2.5 rounded-[10px] border border-green-200 bg-green-50 px-3.5 py-3 text-[13px] leading-[19px] text-green-800 dark:border-green-500/30 dark:bg-green-500/10 dark:text-green-300">
            <IconCheckCircleOutline class="w-[18px] h-[18px] shrink-0" />
            {{ $t('You verified recently, so no code is needed.') }}
          </p>
        </div>

        <div class="af-2fa-footer flex items-center gap-3 border-t border-lightDialogBreakLine bg-gray-50 py-3 pl-6 pr-5 dark:border-darkDialogBreakLine dark:bg-gray-800/50">
          <button v-if="modalMode === 'totp' && doesUserHavePasskeys" type="button" class="af-2fa-switch-to-passkey inline-flex h-11 items-center gap-1.5 text-[13px] font-medium text-lightPrimary hover:underline dark:text-darkPrimary" @click="modalMode = 'passkey'">
            <IconFingerprintOutline class="w-4 h-4" />
            {{ $t('Use passkey instead') }}
          </button>
          <button v-else-if="modalMode === 'passkey'" type="button" class="af-2fa-switch-to-totp inline-flex h-11 items-center gap-1.5 text-[13px] font-medium text-lightPrimary hover:underline dark:text-darkPrimary" @click="modalMode = 'totp'">
            <IconMobilePhoneOutline class="w-4 h-4" />
            {{ $t('Use code instead') }}
          </button>
          <div class="af-2fa-buttons ms-auto flex gap-2">
            <Button variant="secondary" class="af-2fa-cancel-btn" @click="onCancel">{{ $t('Cancel') }}</Button>
            <Button v-if="modalMode === 'passkey'" @click="usePasskeyButtonClick" :disabled="isFetchingPasskey" :loader="isFetchingPasskey" class="af-2fa-passkey-btn gap-2">
              <IconFingerprintOutline class="w-4 h-4" />
              {{ $t('Use passkey') }}
            </Button>
            <Button v-else-if="modalMode === 'grace'" class="af-2fa-approve-btn gap-2" @click="approveInGracePeriod">
              <IconCheckOutline class="w-4 h-4" />
              {{ approveLabel }}
            </Button>
          </div>
        </div>
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
  import {
    IconCheckCircleOutline,
    IconCheckOutline,
    IconCloseOutline,
    IconExclamationCircleOutline,
    IconFingerprintOutline,
    IconMobilePhoneOutline,
    IconShieldCheckOutline,
  } from '@iconify-prerendered/vue-flowbite';
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
      confirmationResult = await twoFactorsAuthApi.get2FaConfirmationResult();
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
  // verifyAuto calls that arrive together are confirmed with one code. A single call lists only its own description.
  const confirmItems = computed(() => {
    const sessions = sessionsToResolve.value;
    if (!sessions.length) {
      return dialogItems.value;
    }
    if (sessions.length === 1) {
      return sessions[0].actionDescription ? [sessions[0].actionDescription] : [];
    }
    return sessions.map((session) => session.actionDescription ?? t('Action without a description'));
  });
  const dialogTitle = computed(() => {
    const count = confirmItems.value.length;
    if (customDialogTitle.value) {
      return customDialogTitle.value;
    }
    if (count > 1) {
      return t('Confirm {count} actions', { count });
    }
    return count ? t('Confirm action') : t("Confirm it's you");
  });
  const approveLabel = computed(() => confirmItems.value.length > 1
    ? t('Approve {count} actions', { count: confirmItems.value.length })
    : t('Approve'));
  const codeError = ref("");
  const otpInputClasses = computed(() => [
    'otp-input w-12 h-14 p-0 rounded-[10px] border-[1.5px] bg-gray-50 text-center text-2xl font-medium leading-none tabular-nums text-gray-900 outline-none focus:ring-4 dark:bg-gray-800 dark:text-white',
    codeError.value
      ? 'border-red-500 focus:border-red-500 focus:ring-red-500/25 dark:border-red-400 dark:focus:border-red-400'
      : 'border-gray-300 focus:border-lightPrimary focus:ring-lightPrimary/25 dark:border-gray-600 dark:focus:border-darkPrimary dark:focus:ring-darkPrimary/25',
  ].join(' '));
  const subtitles = computed(() => ({
    totp: t('Enter the 6-digit code from your authenticator app'),
    passkey: t('Confirm with your passkey'),
    grace: t('Review and approve'),
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
  /* a dash after the 3rd digit splits the code into two groups of three */
  :deep(.otp-input-container > div:nth-child(3))::after {
    content: '';
    width: 0.75rem;
    height: 2px;
    margin-left: 0.5rem;
    border-radius: 1px;
    background: currentColor;
  }
</style>
