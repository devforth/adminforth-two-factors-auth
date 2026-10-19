<template>
  <div class="relative flex items-center justify-center min-h-screen bg-lightHtml dark:bg-darkHtml"
    :style="coreStore.config?.loginBackgroundImage && coreStore.config?.loginBackgroundPosition === 'over' ? {
      'background-image': 'url(' + loadFile(coreStore.config?.loginBackgroundImage) + ')',
      'background-size': 'cover',
      'background-position': 'center',
      'background-blend-mode': coreStore.config?.removeBackgroundBlendMode ? 'normal' : 'darken'
    }: {}"
    >

    <div id="authentication-modal" class="af-two-factors-setup flex items-center justify-center w-full p-4">
      <TwoFaCard
        class="af-login-popup"
        :title="$t('Set up two-factor authentication')"
        :subtitle="$t('Add this account to your authenticator app')"
        :error="codeError"
      >
        <div>
          <p class="mb-3 flex items-center gap-2.5 text-sm font-medium text-lightInputText dark:text-darkInputText">
            <span class="flex w-6 h-6 shrink-0 items-center justify-center rounded-full bg-lightPrimary/10 text-xs font-semibold text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">1</span>
            {{ $t('Scan the QR code with your authenticator app') }}
          </p>
          <div class="flex items-center gap-4 rounded-lg border border-lightDialogBreakLine bg-lightSecondaryDarken p-3.5 dark:border-darkDialogBreakLine dark:bg-darkSecondaryLighten">
            <!-- a QR code needs a white ground to be scanned, in the dark theme too -->
            <div class="w-32 h-32 shrink-0 rounded-lg bg-white p-2">
              <img v-if="totpQrCode" :src="totpQrCode" class="af-qr-code w-full h-full" alt="QR code" />
            </div>
            <div class="flex min-w-0 flex-col gap-2">
              <p class="text-sm leading-5 text-lightInputIconColor dark:text-darkInputIconColor">{{ $t('Setting up on this device?') }}</p>
              <Link :to="totpUri" class="inline-flex items-center gap-1.5 text-sm">
                {{ $t('Open in authenticator app') }}
                <IconExternalLink class="w-4 h-4" />
              </Link>
            </div>
          </div>
        </div>

        <div>
          <p class="mb-2 text-xs font-medium uppercase tracking-wider text-lightInputIconColor dark:text-darkInputIconColor">{{ $t('Or enter the key manually') }}</p>
          <div class="flex items-center gap-2 rounded-lg border border-lightDialogBreakLine bg-lightSecondaryDarken py-1.5 pl-3.5 pr-1.5 dark:border-darkDialogBreakLine dark:bg-darkSecondaryLighten">
            <span class="af-2fa-secret flex-1 min-w-0 select-all break-all font-mono text-sm tracking-wider text-lightInputText dark:text-darkInputText">{{ totp.newSecret }}</span>
            <Button type="button" variant="ghost" iconOnly :aria-label="$t('Copy key')" class="af-2fa-copy-btn" @click="onCopyClick">
              <IconCopy aria-hidden="true" />
            </Button>
          </div>
        </div>

        <TwoFaCodeInput ref="codeInput" :invalid="Boolean(codeError)" @complete="handleOnComplete">
          <template #label>
            <p class="mb-3 flex items-center gap-2.5 text-sm font-medium text-lightInputText dark:text-darkInputText">
              <span class="flex w-6 h-6 shrink-0 items-center justify-center rounded-full bg-lightPrimary/10 text-xs font-semibold text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">2</span>
              {{ $t('Enter the 6-digit code from the app') }}
            </p>
          </template>
        </TwoFaCodeInput>

        <template #footer>
          <Button v-if="skipAllowed" type="button" variant="ghost" class="af-2fa-skip-btn -ms-3.5" @click="handleSkip">
            {{ $t('Skip for now') }}
          </Button>
          <LinkButton to="/login" variant="secondary" class="af-2fa-back-to-login ms-auto whitespace-nowrap">{{ $t('Back to login') }}</LinkButton>
        </template>
      </TwoFaCard>
    </div>
  </div>
</template>


<script setup lang="ts">

import { onMounted, ref, computed, onBeforeMount } from 'vue';
import { useCoreStore } from '@/stores/core';
import { useUserStore } from '@/stores/user';
import { IconCopy, IconExternalLink } from '@iconify-prerendered/vue-lucide';
import { callAdminForthApi, loadFile } from '@/utils';
import { useRouter } from 'vue-router';
import { Button, Link, LinkButton } from '@/afcl';
import adminforth from '@/adminforth';
import TwoFaCard from './TwoFaCard.vue';
import TwoFaCodeInput from './TwoFaCodeInput.vue';
import { useI18n } from 'vue-i18n';
import { useRoute } from 'vue-router';
import { handlePasskeyAlert } from './utils.js';
import { useQRCode } from '@vueuse/integrations/useQRCode'

const { t } = useI18n();
const route = useRoute()

onBeforeMount(() => {
  if (localStorage.getItem('isAuthorized') === 'true') {
    coreStore.fetchMenuAndResource();
    if (route.query.next) {
      router.push(route.query.next.toString());
    } else {
      router.push({ name: 'home' });
    }
  }
})

const codeInput = ref<InstanceType<typeof TwoFaCodeInput> | null>(null);
const codeError = ref(null);
const handleOnComplete = (value) => {
  sendCode(value);
};

const router = useRouter();
const inProgress = ref(false);

const coreStore = useCoreStore();
const user = useUserStore();

const skipAllowed = ref(false);


const error = ref(null);
const totp = ref<{ issuer?: string; userName?: string; newSecret?: string }>({});
const totpJWT = ref(null);
const totpUri = computed(() => {
  const { issuer, userName, newSecret } = totp.value || {};
  if (!issuer || !userName || !newSecret) {
    return '';
  }
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(userName)}`;
  return `otpauth://totp/${label}?secret=${newSecret}&issuer=${encodeURIComponent(issuer)}`;
});
const totpQrCode = useQRCode(totpUri, { width: 200, margin: 1 });

  
function parseJwt(token) {
  // Split the token into its parts
  const base64Url = token.split('.')[1];
  
  // Base64-decode the payload
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));
  
  // Parse the JSON payload
  return JSON.parse(jsonPayload);
} 

function onCopyClick(){
  navigator.clipboard.writeText(totp.value.newSecret ?? '');
  adminforth.alert({message: t('Copied to clipboard'), variant: 'success'})
}

onMounted(async () => {
  coreStore.fetchConfig({ redirectToLoginIfNotLoggedIn: false })
  const resp = await callAdminForthApi({
    path: '/plugin/twofa/initSetup',
    method: 'POST',});
  if (resp && resp.totpJWT){
    totpJWT.value = resp.totpJWT;
  } 
  
  totp.value=parseJwt(totpJWT.value);
  
  const allowSkipResp = await callAdminForthApi({
    path: '/plugin/twofa/skip-allow',
    method: 'GET',
  });

  if (allowSkipResp?.skipAllowed){
    skipAllowed.value = true;
  }
});

async function sendCode (value) {
  inProgress.value = true;

  
  const resp = await callAdminForthApi({
    method: 'POST',
    path: '/plugin/twofa/confirmLogin',
    body: {
      code: value
    }
  })
  if (resp.allowedLogin) {
      localStorage.setItem('twofa-skip-setup', 'false');
      if ( route.meta.isPasskeysEnabled ) {
        handlePasskeyAlert(route.meta.suggestionPeriod, router);
      }
      await user.finishLogin();
  } else {
    codeError.value = resp.error || t('Invalid code');
    codeInput.value!.clear();
  }
}

const handleSkip = async () => {
  localStorage.setItem('twofa-skip-setup', 'true');
  const resp = await callAdminForthApi({
    method: 'POST',
    path: '/plugin/twofa/confirmLogin',
    body: {
      skip: true,
    }
  });
  if (resp.allowedLogin){
      if ( route.meta.isPasskeysEnabled ) {
        handlePasskeyAlert(route.meta.suggestionPeriod, router);
      }
      await user.finishLogin();
  } else if (resp.error) {
    codeError.value = resp.error;
  } else {
    codeError.value = 'Something went wrong';
  }
}
</script>