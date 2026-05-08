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
      <div class="relative w-full max-w-md">
        
        <div class="af-login-popup relative bg-white dark:bg-gray-700 rounded-lg shadow p-6" :class="codeError ? 'rounded-b-none' : ''">
          
          <div class="af-2fa-header flex flex-col items-center justify-center gap-3 mb-6">
            <div class="af-2fa-icon-wrap w-14 h-14 shrink-0 flex items-center justify-center rounded-full bg-lightPrimary dark:bg-darkPrimary">
              <IconShieldOutline class="af-2fa-shield-icon w-7 h-7 text-white" />
            </div>
            <div class="af-2fa-title-wrap text-center">
              <p class="text-xl font-medium text-gray-900 dark:text-white">
                {{ confirmationMode === 'code' ? $t('Two-factor Auth') : $t('Passkey') }}
              </p>
              <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                {{ confirmationMode === 'code' 
                   ? $t('Please enter your authenticator code') 
                   : $t('When you are ready, authenticate using the button below') 
                }}
              </p>
            </div>
          </div>

          <div v-if="confirmationMode === 'code'" class="af-2fa-otp-root flex flex-col items-center gap-6" ref="otpRoot">
            <v-otp-input
              ref="code"
              container-class="grid grid-cols-6 gap-3"
              input-classes="bg-gray-50 text-center flex justify-center otp-input border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-10 h-10 dark:bg-gray-600 dark:border-gray-500 dark:text-white"
              :num-inputs="6"
              inputType="number"
              inputmode="numeric"
              :should-auto-focus="true"
              v-model:value="bindValue"
              @on-complete="handleOnComplete"
            />

            <div class="af-2fa-footer text-center text-xs text-gray-500 dark:text-gray-400">
              <p>
                {{$t('Having trouble?')}}
                <button v-if="doesUserHavePasskeys" type="button" 
                  class="hover-link bg-transparent text-[#16537E] border-none p-0 cursor-pointer ml-1" 
                  @click="router.push({ hash: '#passkey' })">
                  {{$t('Use passkey instead')}}
                </button>
                <span v-if="doesUserHavePasskeys" class="mx-1">{{$t('or')}}</span>
                <Link to="/login" class="hover-link">
                  {{$t('Back to login')}}
                </Link>
              </p>
            </div>
          </div>

          <div v-else class="af-2fa-passkey-root flex flex-col gap-6">
            <Button @click="usePasskeyButton" :disabled="isFetchingPasskey" :loader="isFetchingPasskey" class="af-2fa-passkey-btn w-full flex items-center justify-center gap-2">
              <IconShieldOutline class="w-4 h-4" />
              {{$t('Use passkey to verify')}}
            </Button>

            <div class="af-2fa-footer text-center text-xs text-gray-500 dark:text-gray-400">
              <p>
                {{$t('Having trouble?')}}
                <button type="button" 
                  class="hover-link bg-transparent text-[#16537E] border-none p-0 cursor-pointer ml-1" 
                  @click="router.push({ hash: '#code' })">
                  {{$t('Use TOTP instead')}}
                </button>
                <span class="mx-1">{{$t('or')}}</span>
                <Link to="/login" class="hover-link">
                  {{$t('Back to login')}}
                </Link>
              </p>
            </div>
          </div>
        </div>

        <div v-if="codeError" class="af-two-factors-confirmation-error relative bg-red-100 text-red-700 text-xs px-4 py-2 rounded-b-lg shadow border-t border-red-200 text-center">
          {{ codeError }}
        </div>
      </div>
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
  import { Button, Link, Spinner } from '@/afcl';
  import VOtpInput from "vue3-otp-input";
  import { useI18n } from 'vue-i18n';
  import { useRoute } from 'vue-router'
  import { useRouter } from 'vue-router';
  import { IconShieldOutline } from '@iconify-prerendered/vue-flowbite';
  import ErrorMessage from '@/components/ErrorMessage.vue';
  import { handlePasskeyAlert } from './utils.js';
  
  // Global provided by AdminForth runtime
  declare const adminforth: any;

  const { t } = useI18n();
  const code = ref(null);
  const otpRoot = ref(null);
  const bindValue = ref('');
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
  }

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
      tagOtpInputs();
      if (isPasskeysSupported.value === true) {
        await checkIfUserHasPasskeys();
      }
      if (confirmationMode.value ===  'code') {
        await addEventListenerForOTPInput();
      }
    }
    isLoading.value = false;
  });

  watch(confirmationMode, async (newMode) => {
    if (newMode === 'code') {
      await addEventListenerForOTPInput();
    } else {
      removeEventListenerForOTPInput();
    }
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
    cancelPendingWebAuthn('component-unmount');
  }

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
    removeEventListenerForOTPInput();
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
        secret: null,
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
      }
    }
  }

  function handlePaste(event) {
    event.preventDefault();
    if (event.target.classList.contains('otp-input')) {
      return;
    }
    const pastedText = event.clipboardData?.getData('text') || '';
    if (pastedText.length === 6) { 
      code.value?.fillInput(pastedText);
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
      console.error(t('Error checking if user has passkeys:', error));
    }
  }

  async function usePasskeyButton() {
    // Cancel any stray pending requests from earlier flows
    cancelPendingWebAuthn('button-pressed');
    codeError.value = null;
    isFetchingPasskey.value = true;
    const signIn = await createSignInRequest();
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

  async function createSignInRequest() {
    let response;
    try {
      response = await callAdminForthApi({
        path: `/plugin/passkeys/signInRequest`,
        method: 'POST',
      });
    } catch (error) {
      console.error(t('Error creating sign-in request:', error));
      return;
    }
    if (response.ok === true) {
      return { _options: response.data, challengeId: response.challengeId };
    } else {
      adminforth.alert({message: t('Error creating sign-in request.'), variant: 'danger'});
      codeError.value = 'Error creating sign-in request.';
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
      console.error(t('Error during authentication:', error));
      // Handle specific concurrent/pending request error cases gracefully
      const name = (error && (error.name || error.constructor?.name)) || '';
      const message = (error && error.message) || '';
      if (name === 'AbortError') {
        return null;
      } else if (name === 'NotAllowedError') {
        return null;
      } else if (name === 'InvalidStateError' || name === 'OperationError' || /pending/i.test(message)) {
        adminforth.alert({ message: t('Another security prompt is already open. Please try again.'), variant: 'warning' });
        codeError.value = t('A previous passkey attempt was still pending. Please try again.'); 
        return null;
      } else if (name === 'NotAllowedError') {
        adminforth.alert({ message: t('The operation either timed out or was not allowed'), variant: 'danger' });
        codeError.value = t('The operation either timed out or was not allowed.');
        return null;
      } else {
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


  function getOtpInputs(): HTMLInputElement[] {
    const root = otpRoot.value;
    if (!root) return [];
    return Array.from(root.querySelectorAll('input.otp-input')) as HTMLInputElement[];
  }

  function focusFirstAvailableOtpInput() {
    const inputs = getOtpInputs();
    if (!inputs.length) return;
    const firstEmpty = inputs.find((i) => !i.value);
    (firstEmpty || inputs[0]).focus();
  }

  function handleGlobalFocusIn(event) {
    const inputs = getOtpInputs();
    if (!inputs.length) return;
    const target = event.target as HTMLInputElement | null;
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
      const active = document.activeElement as Element | null;
      const activeInput = active instanceof HTMLInputElement ? active : null;
      if (!activeInput || !inputs.includes(activeInput)) {
        focusFirstAvailableOtpInput();
      }
    });
  }
  </script>

  <style scoped lang='scss'>
    .vue3-2fa-code-input {
      display: flex;
      justify-content: center;
      gap: 1rem;
      margin-bottom: 1rem;
    }
    :deep(.otp-input-container) {
      display: flex;
      gap: 0.75rem;
    }
    .vue3-2fa-code-input-box {
        &[type='text'] {
          @apply  w-10 h-10 text-center text-xl border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500;
        
        }
        
    }

    /**
    * This particular piece of code makes the last input have a gap in the middle.
    */
    .spaced-code-input {
        & .vue3-2fa-code-input-box {
            &:nth-child(3) {
                @apply mr-4;
            }

            &:nth-child(4) {
                @apply ml-4;
            }
        }
    } 

    :deep(.otp-input-container) {
      display: flex;
      gap: 0.75rem;
    }

    .hover-link {
      text-decoration: none !important;
      display: inline-block;
      width: fit-content;
      margin: 0 auto;

      &:hover {
        text-decoration: underline !important;
      }
    }

    button.hover-link {
      font-family: inherit;
      font-size: inherit;
    }
  </style>
