<template>
  <div class="af-2fa-hint flex items-center gap-3.5 rounded-lg border border-lightDialogBreakLine bg-lightSecondaryDarken px-4 py-3.5 dark:border-darkDialogBreakLine dark:bg-darkSecondaryLighten">
    <span class="af-2fa-hint-icon flex w-11 h-11 shrink-0 items-center justify-center rounded-full bg-lightPrimary/10 text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">
      <slot name="icon" />
    </span>
    <p class="af-2fa-hint-text text-sm leading-5 text-lightInputIconColor dark:text-darkInputIconColor">
      <slot />
    </p>
  </div>
</template>
