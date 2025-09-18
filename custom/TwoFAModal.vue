<template>
    <div class="af-two-factors-modal fixed inset-0 z-[9999] flex items-center justify-center bg-black/50 top-0 bottom-0 left-0 right-0"
    v-show ="modelShow">
      <div class="relative bg-white dark:bg-gray-700 rounded-lg shadow p-6 w-full max-w-md">
        <div id="mfaCode-label" class="mb-4 text-gray-700 dark:text-gray-100 text-center">
          {{ $t('Please enter your authenticator code') }}
        </div>
  
        <div class="my-4 w-full flex justify-center" ref="otpRoot">
          <v-otp-input
            ref="code"
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
  
        <div class="mt-6 flex justify-center gap-3">
          <button
            class="px-4 py-2 rounded border bg-gray-100 dark:bg-gray-600"
            @click="onCancel"
            :disabled="inProgress"
          >{{ $t('Cancel') }}</button>
        </div>
      </div>
    </div>
  </template>
  
  <script setup lang="ts">
  import VOtpInput from 'vue3-otp-input';
  import { ref, nextTick, watch } from 'vue';
  import { useUserStore } from '@/stores/user';
  import { useI18n } from 'vue-i18n';
  declare global {
    interface Window {
      adminforthTwoFaModal: {
        getCode: () => Promise<any>;
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

  const modelShow = ref(false);
  let resolveFn: ((code: string) => void) | null = null;
  let verifyingCallback: ((code: string) => boolean) | null = null;
  let verifyFn: null | ((code: string) => Promise<boolean> | boolean) = null;
  let rejectFn: ((err?: any) => void) | null = null;

  window.adminforthTwoFaModal = {
    getCode: (verifyingCallback?: (code: string) => Promise<boolean>) =>
      new Promise((resolve, reject) => {
      if (modelShow.value) throw new Error('Modal is already open');
      modelShow.value = true;
      resolveFn = resolve;
      rejectFn = reject;
      verifyFn = verifyingCallback ?? null;
    }),
  };
  
  const { t } = useI18n();
  const user = useUserStore();
  
  const code = ref<any>(null);
  const otpRoot = ref<HTMLElement | null>(null);
  const bindValue = ref('');
  
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
      code.value?.fillInput(pastedText);
    }
  }
  
  async function handleOnComplete(value: string) {
    await sendCode(value);
  }
  
  async function sendCode(value: string) {
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
    resolveFn(value);
  }
  
  
  function onCancel() {
    modelShow.value = false;
    bindValue.value = '';
    code.value?.clearInput();
    emit('rejected', new Error('cancelled'));
    emit('closed');
  }

  watch(modelShow, async (open) => {
  if (open) {
    await nextTick();
    const htmlRef = document.querySelector('html');
    if (htmlRef) {
      htmlRef.style.overflow = 'hidden';
    }
    tagOtpInputs();
    window.addEventListener('paste', handlePaste);
  } else {
    window.removeEventListener('paste', handlePaste);
    const htmlRef = document.querySelector('html');
    if (htmlRef) {
      htmlRef.style.overflow = '';
    }
    bindValue.value = '';
    code.value?.clearInput();
  }
});

  </script>
  
<style scoped>
  :deep(.otp-input-container) {
    display: flex;
    gap: 0.75rem;
  }
</style>