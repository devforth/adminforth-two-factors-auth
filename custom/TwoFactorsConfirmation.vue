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
        <div class="relative bg-white rounded-lg shadow dark:bg-gray-700 dark:shadow-black text-gray-500" >
            <div class="p-8 w-full max-w-md max-h-full custom-auth-wrapper" >
              <div v-if="confirmationMode === 'code'">
                <div id="mfaCode-label" class="m-4">{{$t('Please enter your authenticator code')}} </div>
                <div class="my-4 w-full flex flex-col gap-4 justify-center" ref="otpRoot">
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
          <ErrorMessage :error="codeError" />
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

  const { t } = useI18n();
  const code = ref(null);
  const otpRoot = ref(null);
  const bindValue = ref('');
  const route = useRoute();
  const router = useRouter();
  const codeError = ref(null);
  const isFetchingPasskey = ref(false);

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
      await nextTick();
      await isCMAAvailable();
      tagOtpInputs();
      if (isPasskeysSupported.value === true) {
        checkIfUserHasPasskeys();
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
      confirmationMode.value = 'passkey';
    } else if ( newRoute.hash === '#code' ) {
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

  function checkIfUserHasPasskeys() {
    callAdminForthApi({
      method: 'POST',
      path: '/plugin/passkeys/checkIfUserHasPasskeys',
    }).then((response) => {
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
  }

  async function usePasskeyButton() {
    isFetchingPasskey.value = true;
    const { _options, challengeId } = await createSignInRequest();
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
    try {
      response = await callAdminForthApi({
        path: `/plugin/passkeys/signInRequest`,
        method: 'POST',
      });
    } catch (error) {
      console.error('Error creating sign-in request:', error);
      return;
    }
    if (response.ok === true) {
      return { _options: response.data, challengeId: response.challengeId };
    } else {
      adminforth.alert({message: 'Error creating sign-in request.', variant: 'warning'});
      codeError.value = 'Error creating sign-in request.';
    }
  }

  async function authenticate(options) {
    try {
      const abortController = new AbortController();
      const credential = await navigator.credentials.get({
        publicKey: options,
        signal: abortController.signal,
      });
      return credential;
    } catch (error) {
      adminforth.alert({message: 'Error during authentication', variant: 'warning'});
      codeError.value = 'Error during authentication.';
    }
  }


  function getOtpInputs() {
    const root = otpRoot.value;
    if (!root) return [];
    return Array.from(root.querySelectorAll('input.otp-input'));
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
