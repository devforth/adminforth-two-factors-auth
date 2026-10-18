<template>
  <div class="af-2fa-code">
    <div :id="LABEL_ID">
      <slot name="label">
        <p class="mb-2 text-sm font-medium text-lightInputText dark:text-darkInputText">{{ $t('Authenticator code') }}</p>
      </slot>
    </div>
    <div class="af-2fa-otp-root flex justify-center">
      <CodeInput
        ref="codeInput"
        id="mfaCode"
        name="mfaCode"
        :aria-labelledby="LABEL_ID"
        :length="CODE_LENGTH"
        :groupSize="3"
        :invalid="invalid"
        autofocus
        keepFocus
        @complete="emit('complete', $event)"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { CodeInput } from '@/afcl';

defineProps<{
  invalid?: boolean;
}>();

const emit = defineEmits<{
  (e: 'complete', code: string): void;
}>();

const CODE_LENGTH = 6;
const LABEL_ID = 'mfaCode-label';

const codeInput = ref<InstanceType<typeof CodeInput> | null>(null);

defineExpose({
  clear: () => codeInput.value!.clear(),
});
</script>
