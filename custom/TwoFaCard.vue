<template>
  <div class="af-2fa-card relative flex flex-col w-full max-w-md overflow-hidden rounded-xl border border-lightDialogBreakLine bg-lightDialogBackgorund shadow-popover dark:border-darkDialogBreakLine dark:bg-darkDialogBackgorund dark:shadow-darkPopover">
    <div class="af-2fa-header flex items-start gap-3.5 border-b border-lightDialogBreakLine py-5 pl-6 dark:border-darkDialogBreakLine" :class="closable ? 'pr-4' : 'pr-6'">
      <div class="af-2fa-icon-wrap flex w-10 h-10 shrink-0 items-center justify-center rounded-lg bg-lightPrimary/10 text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">
        <IconShieldCheck class="af-2fa-shield-icon w-5 h-5" />
      </div>
      <div class="af-2fa-title-wrap flex-1 min-w-0">
        <p class="af-2fa-title break-words text-lg leading-6 font-semibold text-lightDialogHeaderText dark:text-darkDialogHeaderText">{{ title }}</p>
        <p class="af-2fa-subtitle mt-0.5 text-sm leading-5 text-lightInputIconColor dark:text-darkInputIconColor">{{ subtitle }}</p>
      </div>
      <Button
        v-if="closable"
        type="button"
        variant="ghost"
        size="sm"
        iconOnly
        :aria-label="$t('Cancel')"
        class="af-2fa-close-btn -mt-0.5 text-lightDialogCloseButton hover:text-lightDialogCloseButtonHover hover:bg-lightDialogCloseButtonHoverBackground dark:text-darkDialogCloseButton dark:hover:text-darkDialogCloseButtonHover dark:hover:bg-darkDialogCloseButtonHoverBackground"
        @click="emit('close')"
      >
        <IconX aria-hidden="true" />
      </Button>
    </div>

    <div class="af-2fa-body flex flex-col gap-5 px-6 pt-5 pb-6">
      <slot />
      <p v-if="error" role="alert" class="af-2fa-code-error -mt-2.5 flex items-center gap-1.5 text-sm text-lightDanger dark:text-darkDanger">
        <IconCircleAlert class="w-4 h-4 shrink-0" />
        {{ error }}
      </p>
    </div>

    <div v-if="$slots.footer" class="af-2fa-footer flex flex-wrap items-center gap-x-3 gap-y-2 border-t border-lightDialogBreakLine bg-lightFormHeading py-3 pl-6 pr-5 dark:border-darkDialogBreakLine dark:bg-darkFormHeading">
      <slot name="footer" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { IconCircleAlert, IconShieldCheck, IconX } from '@iconify-prerendered/vue-lucide';
import { Button } from '@/afcl';

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
