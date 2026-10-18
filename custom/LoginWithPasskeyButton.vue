<template>

    <!-- right after the OAuth buttons it joins them with their 8px gap instead of the 16px between login page injections -->
    <Button
        variant="secondary"
        class="af-login-with-passkey-btn w-full gap-2 [.af-oauth-login+&]:!mt-2"
        @click="handleLoginWithPasskey"
    >
      <IconFingerprint class="w-4 h-4 text-lightPrimary dark:text-darkPrimary" />
      {{ $t('Continue with Passkey') }}
    </Button>

</template>



<script setup lang="ts">
    import { IconFingerprint } from '@iconify-prerendered/vue-lucide';
    import { getPasskey } from "./utils.js";
    import { callAdminForthApi } from '@/utils';
    import { useUserStore } from '@/stores/user';
    import { Button } from '@/afcl';
    import adminforth from '@/adminforth';
    import { useRouter, useRoute } from 'vue-router';
    import { useI18n } from 'vue-i18n';

    const { t } = useI18n();
    const userStore = useUserStore();
    const router = useRouter();

    async function handleLoginWithPasskey() {
      const passkeyOptions = await getPasskey();
      try {
        const resp = await callAdminForthApi({
        method: 'POST',
        path: '/plugin/twofa/confirmLoginWithPasskey',
        body: {
            passkeyResponse: passkeyOptions
        }
        });
        if ( resp.error ) {
            console.error("Login failed:", resp.error);
            adminforth.alert({message: t('Error: ') + resp.error, variant: 'warning'});
          return;
        }

        if ( resp.allowedLogin === true ) {
            await userStore.finishLogin();
        } else if (resp.redirectTo) {
          router.push(resp.redirectTo);
        } else {
          console.error("Login not allowed:", resp.error);
          adminforth.alert({message: t('Error: ') + (resp.error || t('Login not allowed')), variant: 'warning'});
        }
      } catch (error) {
        console.error("Error during passkey login:", error);
      }
    }
</script>
