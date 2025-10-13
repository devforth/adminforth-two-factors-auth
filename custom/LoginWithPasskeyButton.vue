<template>

    <div
        class="flex items-center justify-center border hover:bg-gray-50 hover:cursor-pointer px-4 py-2 rounded-md text-gray-900 font-medium"
        @click="handleLoginWithPasskey"
    >
        <IconShieldOutline class="w-6 h-6" />
        <span class="ml-2">Continue with Passkey</span>
    </div>

</template>



<script setup lang="ts">
    import { IconShieldOutline } from '@iconify-prerendered/vue-flowbite';
    import { getPasskey } from "./utils.js";
    import { callAdminForthApi } from '@/utils';
    import { useUserStore } from '@/stores/user';

    const userStore = useUserStore();

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
            adminforth.alert({message: 'Error: ' + resp.error, variant: 'warning'});
          return;
        }

        if ( resp.allowedLogin === true ) { 
            await userStore.finishLogin();
        }
      } catch (error) {
        console.error("Error during passkey login:", error);
      } 
    }
</script>