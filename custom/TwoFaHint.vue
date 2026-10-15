<template>
  <div class="af-2fa-hint flex items-center gap-3.5 rounded-lg border border-lightDialogBreakLine bg-gray-50 px-4 py-3.5 dark:border-darkDialogBreakLine dark:bg-gray-800">
    <span class="af-2fa-hint-icon flex w-11 h-11 shrink-0 items-center justify-center rounded-full bg-lightPrimary/10 text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">
      <slot name="icon" />
    </span>
    <p class="af-2fa-hint-text text-sm leading-5 text-gray-500 dark:text-gray-400">
      <slot />
    </p>
  </div>
</template>
