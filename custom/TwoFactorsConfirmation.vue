<template>
    <div class="relative flex items-center justify-center min-h-screen bg-gray-100 dark:bg-gray-800"
      :style="(coreStore.config?.loginBackgroundImage && coreStore.config?.loginBackgroundPosition === 'over') ? {
        'background-image': 'url(' + loadFile(coreStore.config?.loginBackgroundImage) + ')',
        'background-size': 'cover',
        'background-position': 'center',
        'background-blend-mode': coreStore.config?.removeBackgroundBlendMode ? 'normal' : 'darken'
      }: {}"
      >
  
      <div id="authentication-modal" tabindex="-1" class="af-two-factors-confirmation overflow-y-auto overflow-x-hidden z-50 min-w-[00px] justify-center items-center md:inset-0 h-[calc(100%-1rem)] max-h-full">
        <div class="relative p-4 w-full max-w-md max-h-full">
            <!-- Modal content -->
            <div class="relative bg-white rounded-lg shadow dark:bg-gray-700 dark:shadow-black text-gray-500" >
                <div class="p-8 w-full max-w-md max-h-full custom-auth-wrapper" >
                    <div id="mfaCode-label" class="m-4">{{$t('Please enter your authenticator code')}} </div>
                    <div class="my-4 w-full flex justify-center" ref="otpRoot">
                      <v-otp-input
                        ref="code"
                        container-class="grid grid-cols-6 gap-3 w-full"
                        input-classes="bg-gray-50 text-center flex justify-center otp-input  border leading-none border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-10 h-10 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                        :num-inputs="6"
                        inputType="number"
                        inputmode="numeric"
                        :should-auto-focus="true"
                        :should-focus-order="true"
                        v-model:value="bindValue"
                        @on-complete="handleOnComplete"
                      />
                    </div>
                      <div class="mt-6 flex justify-center">
                        <LinkButton
                          to="/login"
                          class="w-[290px] mx-4"
                        >
                          {{$t('Back to login')}}
                        </LinkButton>
                      </div>
                </div>
            </div>
        </div>
    </div>
      
      </div>
       
  
  </template>


  <script setup>

  import { onMounted, nextTick, onBeforeUnmount, ref, watchEffect,computed,watch } from 'vue';
  import { useCoreStore } from '@/stores/core';
  import { useUserStore } from '@/stores/user';
  import { callAdminForthApi, loadFile } from '@/utils';
  import { showErrorTost } from '@/composables/useFrontendApi';
  import { LinkButton } from '@/afcl';
  import VOtpInput from "vue3-otp-input";
  import { useI18n } from 'vue-i18n';

  const { t } = useI18n();
  const code = ref(null);
  const otpRoot = ref(null);
  const bindValue = ref('');

  const handleOnComplete = (value) => {
    sendCode(value);
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


  onMounted(async () => {
    await nextTick();
    tagOtpInputs();
  });

  onBeforeUnmount(() => {
    window.removeEventListener('paste', handlePaste);
  });
  
  async function sendCode (value) {
    inProgress.value = true;
    const resp = await callAdminForthApi({
      method: 'POST',
      path: '/plugin/twofa/confirmSetup',
      body: {
        code: value,
        secret: null,
      }
    })
    if (resp.allowedLogin){
      await user.finishLogin();
    } else {
      showErrorTost(t('Invalid code'));
    }
  }

  // watch(code, async (nv)=>{
  //   if (nv){
  //     sendCode();
  //   }
  // })

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
  </script>

  <style lang='scss'>
    .vue3-2fa-code-input {
      display: flex;
      justify-content: center;
      gap: 1rem;
      margin-bottom: 1rem;
    }
    .otp-input {
      margin: 0 5px;
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
