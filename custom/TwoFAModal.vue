<template>
    <div class="af-two-factors-modal fixed inset-0 z-[9999] flex items-center justify-center bg-black/50 top-0 bottom-0 left-0 right-0 px-4"
    v-if="modelShow && (isLoading === false)">
      <TwoFaCard
        :class="`af-two-factor-modal-${modalMode}`"
        :title="dialogTitle"
        :subtitle="subtitles[modalMode]"
        :error="modalMode === 'totp' ? codeError : ''"
        closable
        @close="onCancel"
      >
        <pre v-if="dialogDetails" class="af-2fa-details max-h-60 overflow-auto rounded-[10px] border border-lightDialogBreakLine bg-gray-50 p-3 text-xs text-gray-800 dark:border-darkDialogBreakLine dark:bg-gray-800 dark:text-gray-100">{{ dialogDetails }}</pre>

        <div v-if="confirmItems.length" class="af-2fa-actions">
          <p class="mb-2 text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ $t('You are approving') }}</p>
          <ul class="af-2fa-actions-list max-h-60 overflow-auto divide-y divide-lightDialogBreakLine rounded-[10px] border border-lightDialogBreakLine bg-gray-50 dark:divide-darkDialogBreakLine dark:border-darkDialogBreakLine dark:bg-gray-800">
            <li v-for="(item, i) in confirmItems" :key="i" class="flex gap-3 px-3.5 py-3">
              <span aria-hidden="true" class="mt-2 w-1.5 h-1.5 shrink-0 rounded-full bg-lightPrimary dark:bg-darkPrimary"></span>
              <span class="min-w-0 text-[15px] leading-[22px] break-words text-gray-800 dark:text-gray-100">{{ item }}</span>
            </li>
          </ul>
        </div>

        <TwoFaCodeInput v-if="modalMode === 'totp'" ref="codeInput" :invalid="Boolean(codeError)" @complete="sendConfirmationResult" />
        <TwoFaHint v-else-if="modalMode === 'passkey'" class="af-2fa-passkey-hint">
          <template #icon><IconFingerprintOutline class="w-6 h-6" /></template>
          {{ $t('Your browser will ask for Touch ID, Windows Hello or a security key.') }}
        </TwoFaHint>
        <p v-else role="status" class="af-2fa-grace-notice flex items-start gap-2.5 rounded-[10px] border border-green-200 bg-green-50 px-3.5 py-3 text-[13px] leading-[19px] text-green-800 dark:border-green-500/30 dark:bg-green-500/10 dark:text-green-300">
          <IconCheckCircleOutline class="w-[18px] h-[18px] shrink-0" />
          {{ $t('You verified recently, so no code is needed.') }}
        </p>

        <template #footer>
          <TwoFaLinkButton v-if="modalMode === 'totp' && doesUserHavePasskeys" class="af-2fa-switch-to-passkey" @click="modalMode = 'passkey'">
            <IconFingerprintOutline class="w-4 h-4" />
            {{ $t('Use passkey instead') }}
          </TwoFaLinkButton>
          <TwoFaLinkButton v-else-if="modalMode === 'passkey'" class="af-2fa-switch-to-totp" @click="modalMode = 'totp'">
            <IconMobilePhoneOutline class="w-4 h-4" />
            {{ $t('Use code instead') }}
          </TwoFaLinkButton>
          <div class="af-2fa-buttons ms-auto flex gap-2 whitespace-nowrap">
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
        </template>
      </TwoFaCard>
    </div>
  </template>
  
  <script setup lang="ts">

  import { ref, computed, watch } from 'vue';
  import { useUserStore } from '@/stores/user';
  import { useI18n } from 'vue-i18n';
  import { callAdminForthApi } from '@/utils';
  import { Link, Button } from '@/afcl';
  import {
    IconCheckCircleOutline,
    IconCheckOutline,
    IconFingerprintOutline,
    IconMobilePhoneOutline,
  } from '@iconify-prerendered/vue-flowbite';
  import { getPasskey } from './utils.js'
  import TwoFaCard from './TwoFaCard.vue';
  import TwoFaCodeInput from './TwoFaCodeInput.vue';
  import TwoFaHint from './TwoFaHint.vue';
  import TwoFaLinkButton from './TwoFaLinkButton.vue';
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
  
  const codeInput = ref<InstanceType<typeof TwoFaCodeInput> | null>(null);
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
    resolveFn?.(dataToReturn);
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
      codeInput.value!.clear();
      return;
    }

    modelShow.value = false;
    codeError.value = "";
    customDialogTitle.value = "";
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
    rejectFn?.("Cancel");
    emit('rejected', new Error('cancelled'));
    emit('closed');
  }

  // The page under the open modal does not scroll.
  watch(modelShow, (open) => {
    document.documentElement.style.overflow = open ? 'hidden' : '';
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
