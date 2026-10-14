<template>
  <div class="relative flex items-center justify-center min-h-screen bg-gray-100 dark:bg-gray-800"
    :style="(coreStore.config?.loginBackgroundImage && coreStore.config?.loginBackgroundPosition === 'over') ? {
      'background-image': 'url(' + loadFile(coreStore.config?.loginBackgroundImage) + ')',
      'background-size': 'cover',
      'background-position': 'center',
      'background-blend-mode': coreStore.config?.removeBackgroundBlendMode ? 'normal' : 'darken'
    }: {}"
  >
    <div v-if="isLoading===false" id="authentication-modal" class="af-two-factors-confirmation flex items-center justify-center w-full p-4">
      <TwoFaCard
        class="af-login-popup"
        :title="$t('Two-factor authentication')"
        :subtitle="confirmationMode === 'code' ? $t('Enter the 6-digit code from your authenticator app') : $t('Confirm with your passkey')"
        :error="codeError"
      >
        <TwoFaCodeInput v-if="confirmationMode === 'code'" ref="codeInput" :invalid="Boolean(codeError)" @complete="handleOnComplete" />
        <TwoFaHint v-else class="af-2fa-passkey-hint">
          <template #icon><IconFingerprintOutline class="w-6 h-6" /></template>
          {{ $t('Your browser will ask for Touch ID, Windows Hello or a security key.') }}
        </TwoFaHint>

        <template #footer>
          <TwoFaLinkButton v-if="confirmationMode === 'code' && doesUserHavePasskeys" class="af-2fa-switch-to-passkey" @click="router.push({ hash: '#passkey' })">
            <IconFingerprintOutline class="w-4 h-4" />
            {{ $t('Use passkey instead') }}
          </TwoFaLinkButton>
          <TwoFaLinkButton v-else-if="confirmationMode === 'passkey'" class="af-2fa-switch-to-totp" @click="router.push({ hash: '#code' })">
            <IconMobilePhoneOutline class="w-4 h-4" />
            {{ $t('Use code instead') }}
          </TwoFaLinkButton>
          <div class="af-2fa-buttons ms-auto flex gap-2 whitespace-nowrap">
            <LinkButton to="/login" variant="secondary" class="af-2fa-back-to-login">{{ $t('Back to login') }}</LinkButton>
            <Button v-if="confirmationMode === 'passkey'" @click="usePasskeyButton" :disabled="isFetchingPasskey" :loader="isFetchingPasskey" class="af-2fa-passkey-btn gap-2">
              <IconFingerprintOutline class="w-4 h-4" />
              {{ $t('Use passkey') }}
            </Button>
          </div>
        </template>
      </TwoFaCard>
    </div>
    <div v-else>
      <Spinner class="w-10 h-10" />
    </div>
  </div>
</template>


  <script setup lang="ts">

  import { onMounted, nextTick, onBeforeUnmount, ref, watch, onBeforeMount } from 'vue';
  import { useCoreStore } from '@/stores/core';
  import { useUserStore } from '@/stores/user';
  import { callAdminForthApi, loadFile } from '@/utils';
  import { showErrorTost } from '@/composables/useFrontendApi';
  import { Button, LinkButton, Spinner } from '@/afcl';
  import { useI18n } from 'vue-i18n';
  import { useRoute } from 'vue-router'
  import { useRouter } from 'vue-router';
  import { IconFingerprintOutline, IconMobilePhoneOutline } from '@iconify-prerendered/vue-flowbite';
  import ErrorMessage from '@/components/ErrorMessage.vue';
  import { handlePasskeyAlert } from './utils.js';
  import TwoFaCard from './TwoFaCard.vue';
  import TwoFaCodeInput from './TwoFaCodeInput.vue';
  import TwoFaHint from './TwoFaHint.vue';
  import TwoFaLinkButton from './TwoFaLinkButton.vue';

  // Global provided by AdminForth runtime
  declare const adminforth: any;

  const { t } = useI18n();
  const codeInput = ref<InstanceType<typeof TwoFaCodeInput> | null>(null);
  const route = useRoute();
  const router = useRouter();
  const codeError = ref(null);
  const isFetchingPasskey = ref(false);

  // Shared WebAuthn state to prevent concurrent navigator.credentials.get calls
  const webAuthn = {
    controller: null as AbortController | null,
    inFlight: false,
  };

  function cancelPendingWebAuthn(reason?: string) {
    try {
      if (webAuthn.controller) {
        // Abort any pending WebAuthn request
        webAuthn.controller.abort();
      }
    } catch (e) {
      // no-op
    } finally {
      webAuthn.controller = null;
      webAuthn.inFlight = false;
      if (reason) {
        console.debug('[WebAuthn] Aborted pending request:', reason);
      }
    }
  }

  onBeforeMount(() => {
    if (localStorage.getItem('isAuthorized') === 'true') {
      coreStore.fetchMenuAndResource();
      if (route.query.next) {
        router.push(route.query.next.toString());
      } else {
        router.push({ name: 'home' });
      }
    }
  })

  const handleOnComplete = (value) => {
    sendCode(value, 'TOTP', null);
  };

  const inProgress = ref(false);

  const coreStore = useCoreStore();
  const user = useUserStore();
  const doesUserHavePasskeys = ref(false);
  const confirmationMode = ref("code");
  const isPasskeysSupported = ref(false);
  const isLoading = ref(true);

  onMounted(async () => {
    if (localStorage.getItem('isAuthorized') !== 'true') {
      // Safety: ensure no pending WebAuthn request survives SPA navigation
      cancelPendingWebAuthn('mount-init');
      await nextTick();
      await isCMAAvailable();
      if (isPasskeysSupported.value === true) {
        await checkIfUserHasPasskeys();
      }
    }
    isLoading.value = false;
  });

  watch(route, (newRoute) => {
    codeError.value = null;
    if ( newRoute.hash === '#passkey' ) {
      cancelPendingWebAuthn('switch-to-passkey');
      confirmationMode.value = 'passkey';
      usePasskeyButton();
    } else if ( newRoute.hash === '#code' ) {
      cancelPendingWebAuthn('switch-to-code');
      confirmationMode.value = 'code';
    }
  });

  async function isCMAAvailable() {
    if (window.PublicKeyCredential &&  
    PublicKeyCredential.isConditionalMediationAvailable) {  
      const isCMA = await PublicKeyCredential.isConditionalMediationAvailable();  
      if (isCMA) {  
        isPasskeysSupported.value = true;
      }  
    }
  }

  onBeforeUnmount(() => {
    // Abort any in-flight WebAuthn request when leaving the component
    cancelPendingWebAuthn('component-unmount');
  });

  async function sendCode (value: any, factorMode: 'TOTP' | 'passkey', passkeyOptions: any) {
    inProgress.value = true;
    const usePasskey = factorMode === 'passkey';
    const resp = await callAdminForthApi({
      method: 'POST',
      path: '/plugin/twofa/confirmLogin',
      body: {
        code: value,
        usePasskey: usePasskey,
        passkeyOptions: passkeyOptions,
      }
    })
    if ( resp.allowedLogin ) {
      if ( route.meta.isPasskeysEnabled && !doesUserHavePasskeys.value ) {
        handlePasskeyAlert(route.meta.suggestionPeriod, router);
      }
      await user.finishLogin();
    } else {
      if (usePasskey) {
        showErrorTost(t(resp.error));
        codeError.value = resp.error || t('Passkey authentication failed');
      } else {
        showErrorTost(t(resp.error));
        codeError.value = resp.error || t('Invalid code');
        codeInput.value!.clear();
      }
    }
  }

  async function checkIfUserHasPasskeys() {
    if(!route.meta.isPasskeysEnabled) {
      return;
    }
    try {
      await callAdminForthApi({
        method: 'POST',
        path: '/plugin/passkeys/checkIfUserHasPasskeys',
      }).then(async (response) => {
        if (response.ok) {
          doesUserHavePasskeys.value = response.hasPasskeys;
          if ( doesUserHavePasskeys.value === true ) {
            router.push({ hash: '#passkey' })
            confirmationMode.value = 'passkey';
          } else {
            router.push({ hash: '#code' })
          }
        }
      });
    } catch (error) {
      console.error('Error checking if user has passkeys:', error);
    }
  }

  async function usePasskeyButton() {
    // Cancel any stray pending requests from earlier flows
    cancelPendingWebAuthn('button-pressed');
    codeError.value = null;
    isFetchingPasskey.value = true;
    const signIn = await createLoginOptions();
    if (!signIn) {
      isFetchingPasskey.value = false;
      return;
    }
    const { _options, challengeId } = signIn;
    let options;
    try {
      options = PublicKeyCredential.parseRequestOptionsFromJSON(_options);
    } catch (e) {
      console.error('Error parsing request options:', e);
      adminforth.alert({message: t('Error initiating passkey authentication.'), variant: 'danger'});
      return;
    }
    const credential = await authenticate(options);
    if (!credential) {
      isFetchingPasskey.value = false;
      return;
    }
    const result = JSON.stringify(credential);
    const passkeyOptions = {
      response: result,
      challengeId: challengeId,
      origin: window.location.origin,
    };
    sendCode('', 'passkey', passkeyOptions);
    isFetchingPasskey.value = false;
  }

  async function createLoginOptions() {
    let response;
    try {
      response = await callAdminForthApi({
        path: `/plugin/passkeys/loginOptions`,
        method: 'POST',
      });
    } catch (error) {
      console.error('Error creating sign-in request:', error);
      return;
    }
    if (response.ok === true) {
      return { _options: response.data, challengeId: response.challengeId };
    } else {
      const message = response.error || t('Error creating sign-in request.');
      adminforth.alert({message, variant: 'danger'});
      codeError.value = message;
    }
  }

  let controller = new AbortController();

  async function authenticate(options) {
    controller.abort();
    try {
      // Guard: prevent concurrent navigator.credentials.get calls
      if (webAuthn.inFlight) {
        console.warn('[WebAuthn] A request is already in flight. Aborting previous and retrying.');
        cancelPendingWebAuthn('pre-auth-guard');
      }

      const abortController = new AbortController();
      webAuthn.controller = abortController;
      webAuthn.inFlight = true;

      const credential = await navigator.credentials.get({
        publicKey: options,
        signal: abortController.signal,
        // mediation can be set if using conditional UI, omitted here intentionally
      });
      return credential;
    } catch (error) {
      // Handle specific concurrent/pending request error cases gracefully
      const name = (error && (error.name || error.constructor?.name)) || '';
      const message = (error && error.message) || '';
      if (name === 'AbortError') {
        // Aborted intentionally; no user-facing error needed
        return null;
      } else if (name === 'NotAllowedError') {
        // User cancelled or ignored the browser passkey prompt.
        return null;
      } else if (name === 'InvalidStateError' || name === 'OperationError' || /pending/i.test(message)) {
        adminforth.alert({ message: t('Another security prompt is already open. Please try again.'), variant: 'warning' });
        codeError.value = t('A previous passkey attempt was still pending. Please try again.');
        return null;
      } else {
        console.error('Error during authentication:', error);
        adminforth.alert({message: t(`Error during authentication: ${error}`), variant: 'warning'});
        codeError.value = t('Error during authentication.');
        return null;
      }
    }
    finally {
      // Clear in-flight state regardless of outcome
      webAuthn.inFlight = false;
      webAuthn.controller = null;
    }
  }
  </script>
