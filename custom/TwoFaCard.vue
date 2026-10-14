<template>
  <div class="af-2fa-card relative flex flex-col w-full max-w-[460px] overflow-hidden rounded-xl border border-lightDialogBreakLine bg-lightDialogBackgorund shadow-2xl dark:border-darkDialogBreakLine dark:bg-darkDialogBackgorund">
    <div class="af-2fa-header flex items-start gap-3.5 border-b border-lightDialogBreakLine py-5 pl-6 dark:border-darkDialogBreakLine" :class="closable ? 'pr-4' : 'pr-6'">
      <div class="af-2fa-icon-wrap flex w-10 h-10 shrink-0 items-center justify-center rounded-[10px] bg-lightPrimary/10 text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">
        <IconShieldCheckOutline class="af-2fa-shield-icon w-6 h-6" />
      </div>
      <div class="af-2fa-title-wrap flex-1 min-w-0">
        <p class="af-2fa-title text-[17px] leading-6 font-semibold text-lightDialogHeaderText dark:text-darkDialogHeaderText">{{ title }}</p>
        <p class="af-2fa-subtitle mt-0.5 text-[13px] leading-[18px] text-gray-500 dark:text-gray-400">{{ subtitle }}</p>
      </div>
      <button v-if="closable" type="button" :aria-label="$t('Cancel')" class="af-2fa-close-btn -mt-1 inline-flex w-9 h-9 shrink-0 items-center justify-center rounded-lg text-lightDialogCloseButton hover:bg-lightDialogCloseButtonHoverBackground hover:text-lightDialogCloseButtonHover dark:text-darkDialogCloseButton dark:hover:bg-darkDialogCloseButtonHoverBackground dark:hover:text-darkDialogCloseButtonHover" @click="emit('close')">
        <IconCloseOutline class="w-5 h-5" />
      </button>
    </div>

    <div class="af-2fa-body flex flex-col gap-5 px-6 pt-5 pb-6">
      <slot />
      <p v-if="error" role="alert" class="af-2fa-code-error -mt-2.5 flex items-center gap-1.5 text-[13px] text-red-600 dark:text-red-400">
        <IconExclamationCircleOutline class="w-4 h-4 shrink-0" />
        {{ error }}
      </p>
    </div>

    <div v-if="$slots.footer" class="af-2fa-footer flex flex-wrap items-center gap-x-3 gap-y-2 border-t border-lightDialogBreakLine bg-gray-50 py-3 pl-6 pr-5 dark:border-darkDialogBreakLine dark:bg-gray-800/50">
      <slot name="footer" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { IconCloseOutline, IconExclamationCircleOutline, IconShieldCheckOutline } from '@iconify-prerendered/vue-flowbite';

defineProps<{
  title: string;
  subtitle: string;
  error?: string | null;
  closable?: boolean;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
}>();
</script>
