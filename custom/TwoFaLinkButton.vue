<template>
  <!-- the negative margin lines the label up with the card content -->
  <Button type="button" variant="ghost" class="af-2fa-link-btn -ms-3.5">
    <slot />
  </Button>
</template>

<script setup lang="ts">
import { Button } from '@/afcl';
</script>
