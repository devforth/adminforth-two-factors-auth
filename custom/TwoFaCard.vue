<template>
  <DialogPanel
    class="af-2fa-card"
    :title="title"
    :subtitle="subtitle"
    :error="error"
    :closable="closable"
    :classes="{
      header: 'af-2fa-header',
      icon: 'af-2fa-icon-wrap',
      titleWrap: 'af-2fa-title-wrap',
      title: 'af-2fa-title',
      subtitle: 'af-2fa-subtitle',
      close: 'af-2fa-close-btn',
      body: 'af-2fa-body',
      error: 'af-2fa-code-error',
      footer: 'af-2fa-footer',
    }"
    @close="emit('close')"
  >
    <template #icon>
      <IconShieldCheck class="af-2fa-shield-icon" />
    </template>
    <slot />
    <template v-if="$slots.footer" #footer>
      <slot name="footer" />
    </template>
  </DialogPanel>
</template>

<script setup lang="ts">
import { IconShieldCheck } from '@iconify-prerendered/vue-lucide';
import { DialogPanel } from '@/afcl';

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
