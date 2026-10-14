<template>
  <div class="af-2fa-code">
    <div :id="LABEL_ID">
      <slot name="label">
        <p class="mb-2 text-[13px] font-medium text-gray-700 dark:text-gray-300">{{ $t('Authenticator code') }}</p>
      </slot>
    </div>
    <div ref="otpRoot" class="af-2fa-otp-root text-gray-300 dark:text-gray-500">
      <v-otp-input
        ref="otpInput"
        :input-classes="inputClasses"
        :num-inputs="CODE_LENGTH"
        inputType="number"
        inputmode="numeric"
        :should-auto-focus="true"
        :should-focus-order="true"
        @on-complete="emit('complete', $event)"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import VOtpInput from 'vue3-otp-input';
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';

const props = defineProps<{
  invalid?: boolean;
}>();

const emit = defineEmits<{
  (e: 'complete', code: string): void;
}>();

const CODE_LENGTH = 6;
const LABEL_ID = 'mfaCode-label';
const INPUT_CLASS = 'otp-input';

const otpRoot = ref<HTMLElement | null>(null);
const otpInput = ref<{ clearInput(): void; fillInput(value: string): void } | null>(null);

const inputClasses = computed(() => [
  `${INPUT_CLASS} w-12 h-14 p-0 rounded-[10px] border-[1.5px] bg-gray-50 text-center text-2xl font-medium leading-none tabular-nums text-gray-900 outline-none focus:ring-4 dark:bg-gray-800 dark:text-white`,
  props.invalid
    ? 'border-red-500 focus:border-red-500 focus:ring-red-500/25 dark:border-red-400 dark:focus:border-red-400'
    : 'border-gray-300 focus:border-lightPrimary focus:ring-lightPrimary/25 dark:border-gray-600 dark:focus:border-darkPrimary dark:focus:ring-darkPrimary/25',
].join(' '));

// Focus callbacks are deferred with requestAnimationFrame and may run after unmount, when the root is gone.
function getInputs(): HTMLInputElement[] {
  return otpRoot.value ? Array.from(otpRoot.value.querySelectorAll<HTMLInputElement>(`input.${INPUT_CLASS}`)) : [];
}

function focusFirstEmptyInput() {
  const inputs = getInputs();
  (inputs.find((input) => !input.value) ?? inputs[0])?.focus();
}

// While the code is asked, focus stays in the code inputs, so typing and pasting always go into the code.
function handleFocusIn(event: FocusEvent) {
  if (!getInputs().includes(event.target as HTMLInputElement)) {
    requestAnimationFrame(focusFirstEmptyInput);
  }
}

function handleFocusOut() {
  requestAnimationFrame(() => {
    if (!getInputs().includes(document.activeElement as HTMLInputElement)) {
      focusFirstEmptyInput();
    }
  });
}

// A paste into one of the inputs is handled by vue3-otp-input itself.
function handlePaste(event: ClipboardEvent) {
  event.preventDefault();
  if ((event.target as HTMLElement).classList.contains(INPUT_CLASS)) {
    return;
  }
  const pastedText = event.clipboardData?.getData('text') ?? '';
  if (pastedText.length === CODE_LENGTH) {
    otpInput.value!.fillInput(pastedText);
  }
}

function tagInputs() {
  getInputs().forEach((input, index) => {
    input.setAttribute('name', 'mfaCode');
    input.setAttribute('id', `mfaCode-${index + 1}`);
    input.setAttribute('autocomplete', 'one-time-code');
    input.setAttribute('aria-labelledby', LABEL_ID);
  });
}

onMounted(() => {
  tagInputs();
  focusFirstEmptyInput();
  document.addEventListener('focusin', handleFocusIn, true);
  otpRoot.value!.addEventListener('focusout', handleFocusOut, true);
  window.addEventListener('paste', handlePaste);
});

onBeforeUnmount(() => {
  document.removeEventListener('focusin', handleFocusIn, true);
  otpRoot.value!.removeEventListener('focusout', handleFocusOut, true);
  window.removeEventListener('paste', handlePaste);
});

defineExpose({
  clear: () => otpInput.value!.clearInput(),
});
</script>

<style scoped>
  /* vue3-otp-input renders its own container and ignores container classes, so it is styled here */
  :deep(.otp-input-container) {
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
  }

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
