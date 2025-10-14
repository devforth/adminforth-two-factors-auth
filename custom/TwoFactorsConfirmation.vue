<template>
  <div class="relative flex items-center justify-center min-h-screen bg-gray-100 dark:bg-gray-800"
    :style="(coreStore.config?.loginBackgroundImage && coreStore.config?.loginBackgroundPosition === 'over') ? {
      'background-image': 'url(' + loadFile(coreStore.config?.loginBackgroundImage) + ')',
      'background-size': 'cover',
      'background-position': 'center',
      'background-blend-mode': coreStore.config?.removeBackgroundBlendMode ? 'normal' : 'darken'
    }: {}"
  >

  <div v-if="isLoading===false" id="authentication-modal" tabindex="-1" class="af-two-factors-confirmation overflow-y-auto overflow-x-hidden z-50 min-w-[00px] justify-center items-center md:inset-0 h-[calc(100%-1rem)] max-h-full">
    <div class="relative p-4 w-full max-w-md max-h-full">
        <!-- Modal content -->
        <div class="relative bg-white rounded-lg shadow dark:bg-gray-700 dark:shadow-black text-gray-500" :class="codeError ? 'rounded-b-none' : ''">
            <div class="p-8 w-full max-w-md max-h-full custom-auth-wrapper" >
              <div v-if="confirmationMode === 'code'">
                <div id="mfaCode-label" class="mx-4">{{$t('Please enter your authenticator code')}} </div>
                <div class="mt-4 w-full flex flex-col gap-4 justify-center" ref="otpRoot">
                  <v-otp-input
                    ref="code"
                    container-class="grid grid-cols-6 gap-3 w-full"
                    input-classes="bg-gray-50 text-center justify-center otp-input  border leading-none border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-10 h-10 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                    :num-inputs="6"
                    inputType="number"
                    inputmode="numeric"
                    :should-auto-focus="true"
                    :should-focus-order="true"
                    v-model:value="bindValue"
                    @on-complete="handleOnComplete"
                  />
                  <div class="flex items-center justify-between w-full">
                    <Link v-if="confirmationMode === 'code' && doesUserHavePasskeys" :to="{ hash: '#passkey' }" class="w-max underline hover:no-underline hover:cursor-pointer text-lightPrimary whitespace-nowrap">Use passkey</Link>
                    <Link
                      v-if="confirmationMode === 'code'"
                      to="/login"
                      class="w-max"
                    >
                      {{$t('Back to login')}}
                    </Link>
                  </div>
                </div>
              </div>
              <div v-else class="flex flex-col items-center justify-center py-4 gap-6">
                <IconShieldOutline class="w-16 h-16 text-lightPrimary dark:text-darkPrimary"/>
                <p class="text-4xl font-semibold mb-4">Passkey</p>
                <p class="mb-2 max-w-[300px]">When you are ready, authenticate using the button below</p>
                <Button @click="usePasskeyButton" :disabled="isFetchingPasskey" :loader="isFetchingPasskey" class="w-full mx-16">
                  Use passkey
                </Button>
                <div v-if="confirmationMode === 'passkey'" class="max-w-sm px-6 pt-3 w-full bg-white border border-gray-200 rounded-lg shadow-sm dark:bg-gray-800 dark:border-gray-700">
                  <p class="mb-3 font-normal text-gray-700 dark:text-gray-400">
                    Have issues with passkey?
                    <div v-if="doesUserHavePasskeys" class="flex justify-start cursor-pointer gap-2" >
                      <Link v-if="confirmationMode === 'passkey'" :to="{ hash: '#code' }" class="underline hover:no-underline text-lightPrimary whitespace-nowrap">use TOTP</Link>
                      <p> or </p>
                      <Link
                        to="/login"
                        class="w-full"
                      >
                        {{$t('back to login')}}
                      </Link> 
                    </div>
                  </p>
                </div>
              </div>
            </div>
        </div>
        <div
          v-if="codeError"
          class="relative top-full left-0 bg-red-100 text-red-700 text-sm px-2 py-2 rounded-b-lg shadow"
        >
          <p class="pl-6">{{ codeError }} </p>
        </div>
        <div v-else class="h-[36px] opacity-0">
          
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
      console.log("Checking if device supports passkeys:", isPasskeysSupported.value);
      if (isPasskeysSupported.value === true) {
        console.log("Device supports passkeys, checking if user has passkeys...");
        await checkIfUserHasPasskeys();
        console.log("Does user have passkeys:", doesUserHavePasskeys.value);
      }
      document.addEventListener('focusin', handleGlobalFocusIn, true);
      focusFirstAvailableOtpInput();
      const rootEl = otpRoot.value;
      rootEl && rootEl.addEventListener('focusout', handleFocusOut, true);
    }
    isLoading.value = false;
  });

  watch(route, (newRoute) => {
    codeError.value = null;
    if ( newRoute.hash === '#passkey' ) {
      cancelPendingWebAuthn('switch-to-passkey');
      confirmationMode.value = 'passkey';
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
    window.removeEventListener('paste', handlePaste);
    document.removeEventListener('focusin', handleGlobalFocusIn, true);
    const rootEl = otpRoot.value;
    rootEl && rootEl.removeEventListener('focusout', handleFocusOut, true);
    // Abort any in-flight WebAuthn request when leaving the component
    cancelPendingWebAuthn('component-unmount');
  });

  async function sendCode (value: any, factorMode: 'TOTP' | 'passkey', passkeyOptions: any) {
    inProgress.value = true;
    const usePasskey = factorMode === 'passkey';
    console.log("Sending code with factorMode:", factorMode);
    console.log("Passkey options:", passkeyOptions);
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
    console.log("Response from confirmLogin:", resp);
    if ( resp.allowedLogin ) {
      if ( route.meta.isPasskeysEnabled && !doesUserHavePasskeys.value ) {
        handlePasskeyAlert(route.meta.suggestionPeriod, router);
      }
      console.log("Login confirmed, finishing login...");
      await user.finishLogin();
    } else {
      console.log("Login not allowed, showing error:", resp.error);
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
    const signIn = await createSignInRequest();
    if (!signIn) {
      isFetchingPasskey.value = false;
      return;
    }
    const { _options, challengeId } = signIn;
    const options = PublicKeyCredential.parseRequestOptionsFromJSON(_options);
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
    console.log("Creating sign-in request for passkey...");
    try {
      response = await callAdminForthApi({
        path: `/plugin/passkeys/signInRequest`,
        method: 'POST',
      });
    } catch (error) {
      console.log("Error creating sign-in request:", error);
      console.error('Error creating sign-in request:', error);
      return;
    }
    console.log("Sign-in request response:", response);
    if (response.ok === true) {
      return { _options: response.data, challengeId: response.challengeId };
    } else {
      adminforth.alert({message: 'Error creating sign-in request.', variant: 'warning'});
      codeError.value = 'Error creating sign-in request.';
    }
  }

  let controller = new AbortController();

  async function authenticate(options) {
    console.log("Authenticating with options:", options);
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
      console.log("Credential obtained:", credential);
      return credential;
    } catch (error) {
      console.error('Error during authentication:', error);
      // Handle specific concurrent/pending request error cases gracefully
      const name = (error && (error.name || error.constructor?.name)) || '';
      const message = (error && error.message) || '';
      if (name === 'AbortError') {
        // Aborted intentionally; no user-facing error needed
        return null;
      } else if (name === 'InvalidStateError' || name === 'OperationError' || /pending/i.test(message)) {
        adminforth.alert({ message: t('Another security prompt is already open. Please try again.'), variant: 'warning' });
        codeError.value = t('A previous passkey attempt was still pending. Please try again.');
        return null;
      } else if (name === 'NotAllowedError') {
        adminforth.alert({ message: `The operation either timed out or was not allowed`, variant: 'warning' });
        codeError.value = 'The operation either timed out or was not allowed.';
        return null;
      } else {
        adminforth.alert({message: `Error during authentication: ${error}`, variant: 'warning'});
        codeError.value = 'Error during authentication.';
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
  </style>
