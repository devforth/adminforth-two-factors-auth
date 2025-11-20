<template>

    <Button
        class="w-full !py-2"
        @click="handleLoginWithPasskey"
    >
      <div class="flex items-center justify-center">
        <IconShieldOutline class="w-6 h-6 mr-1" />
        <span>{{ $t('Continue with Passkey') }}</span>
      </div>
    </Button>

</template>



<script setup lang="ts">
    import { IconShieldOutline } from '@iconify-prerendered/vue-flowbite';
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