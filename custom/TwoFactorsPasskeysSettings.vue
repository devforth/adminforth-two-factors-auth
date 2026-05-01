<template>
    <div class="af-passkeys flex flex-col justify-center mr-6 md:mr-12">
        <h2 class="af-passkeys-title flex items-start justify-start leading-none text-gray-800 dark:text-gray-50 text-3xl font-semibold">{{$t('Passkeys')}}</h2>
        <p class="af-passkeys-subtitle text-sm mt-3"> {{$t('Manage your passwordless authentication methods')}} </p>

        <div class="af-passkeys-grid mt-6 flex flex-wrap gap-4">
            <div
                v-for="item in passkeys"
                :key="item.id"
                class="af-passkey-card flex flex-col w-full h-42 lg:w-72 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl p-4 shadow-sm"
            >
                <div class="af-passkey-card-header flex items-center gap-3 mb-3">
                    <div class="af-passkey-card-icon w-10 h-10 flex items-center justify-center bg-gray-100 dark:bg-gray-700 rounded-lg shrink-0">
                        <img class="max-h-6 max-w-6" :src="coreStore.theme === 'light' ? item.light_icon : item.dark_icon" />
                    </div>
                    <div class="af-passkey-card-info flex-1 min-w-0">
                        <p class="af-passkey-card-name font-semibold text-gray-900 dark:text-white truncate" :title="item.name">{{ item.name }}</p>
                        <p class="af-passkey-card-type text-xs text-gray-500 dark:text-gray-400">{{$t('Synced passkey')}}</p>
                    </div>
                    <span class="af-passkey-card-badge shrink-0 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                        {{$t('Active')}}
                    </span>
                </div>

                <div class="af-passkey-card-last-used text-xs text-gray-500 dark:text-gray-400 mb-4">
                    <span class="af-passkey-card-last-used-label font-medium">{{$t('Last used')}}:</span>
                    <span v-if="item.last_used_at" class="af-passkey-card-last-used-date ml-1">{{ formatDateTime(item.last_used_at) }}</span>
                    <span v-else class="af-passkey-card-last-used-never ml-1 italic">{{$t('Never')}}</span>
                </div>

                <div class="af-passkey-card-actions grid grid-cols-2 gap-2 mt-auto">
                    <Dialog
                        class="edit-passkey-confirmation-dialog w-96"
                        :buttons="[
                            { label: 'Cancel', options: { class: 'dialog-cancel-button w-full' }, onclick: (dialog) => { passkeysNewName = ''; dialog.hide(); } },
                            { label: 'Save', options: { class: 'dialog-save-button w-full' }, onclick: (dialog) => { renamePasskey(item.id, passkeysNewName); dialog.hide(); } },
                        ]"
                        header="Edit Passkey"
                    >
                        <template #trigger>
                            <button
                                @click="passkeysNewName = ''"
                                class="af-passkey-btn-rename w-full flex items-center justify-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg border border-gray-200 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors cursor-pointer"
                            >
                                <IconPenSolid class="w-3.5 h-3.5" />
                                {{$t('Rename')}}
                            </button>
                        </template>
                        <div class="flex flex-col gap-2">
                            <label class="text-sm font-medium">{{$t('Current name:')}}</label>
                            <p class="font-medium text-sm text-gray-900 dark:text-white pb-2 truncate" :title="item.name">{{ item.name }}</p>
                            <label class="text-sm font-medium">{{$t('Enter new passkey name:')}}</label>
                            <Input
                                v-model="passkeysNewName"
                                type="text"
                                class="w-full"
                                :placeholder="$t('New name')"
                            />
                        </div>
                    </Dialog>

                    <button
                        @click="confirmAndDelete(item.id)"
                        class="af-passkey-btn-remove flex items-center justify-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 transition-colors cursor-pointer"
                    >
                        <IconTrashBinSolid class="w-3.5 h-3.5" />
                        {{$t('Remove')}}
                    </button>
                </div>
            </div>

            <template v-if="isInitialFinished">
                <Tooltip v-if="!isPasskeySupported && (authenticatorAttachment === 'platform' || authenticatorAttachment === 'both')">
                    <div class="af-passkey-add-card af-passkey-add-local flex flex-col items-center justify-center gap-2 p-4 rounded-xl border-2 border-dashed border-gray-300 dark:border-gray-600 w-full lg:w-72 min-h-36 opacity-50 pointer-events-none">
                        <div class="af-passkey-add-card-icon w-10 h-10 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700">
                            <IconPlusOutline class="w-5 h-5 text-gray-500 dark:text-gray-400" />
                        </div>
                        <p class="af-passkey-add-card-title font-medium text-gray-700 dark:text-gray-300 text-sm">{{$t('Add local passkey')}}</p>
                        <p class="af-passkey-add-card-subtitle text-xs text-gray-400 dark:text-gray-500 text-center">{{$t('Register this device')}}</p>
                    </div>
                    <template #tooltip>
                        <p class="max-w-64">{{$t('This browser or device is reporting partial passkey support.')}}</p>
                        <p class="max-w-64">{{$t('To fix it try to install extention or change browser.')}}</p>
                    </template>
                </Tooltip>

                <div
                    v-else-if="authenticatorAttachment === 'platform' || authenticatorAttachment === 'both'"
                    @click="addLocalPasskey"
                    class="af-passkey-add-card af-passkey-add-local flex flex-col items-center justify-center gap-2 p-4 rounded-xl border-2 border-dashed border-gray-300 dark:border-gray-600 hover:border-blue-400 dark:hover:border-blue-500 hover:bg-blue-50/50 dark:hover:bg-blue-900/10 transition-colors w-full lg:w-72 min-h-36"
                    :class="isFetchingPasskey ? 'opacity-50 pointer-events-none' : 'cursor-pointer'"
                >
                    <div class="af-passkey-add-card-icon w-10 h-10 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700">
                        <Spinner v-if="isFetchingPasskey && addPasskeyMode === 'platform'" class="w-5 h-5" />
                        <IconPlusOutline v-else class="w-5 h-5 text-gray-500 dark:text-gray-400" />
                    </div>
                    <p class="af-passkey-add-card-title font-medium text-gray-700 dark:text-gray-300 text-sm">{{$t('Add local passkey')}}</p>
                    <p class="af-passkey-add-card-subtitle text-xs text-gray-400 dark:text-gray-500 text-center">{{$t('Register this device')}}</p>
                </div>

                <div
                    v-if="authenticatorAttachment === 'cross-platform' || authenticatorAttachment === 'both'"
                    @click="addCrossDevicePasskey"
                    class="af-passkey-add-card af-passkey-add-cross flex flex-col items-center justify-center gap-2 p-4 rounded-xl border-2 border-dashed border-gray-300 dark:border-gray-600 hover:border-purple-400 dark:hover:border-purple-500 hover:bg-purple-50/50 dark:hover:bg-purple-900/10 transition-colors w-full lg:w-72 min-h-36"
                    :class="isFetchingPasskey ? 'opacity-50 pointer-events-none' : 'cursor-pointer'"
                >
                    <div class="af-passkey-add-card-icon w-10 h-10 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700">
                        <Spinner v-if="isFetchingPasskey && addPasskeyMode === 'cross-platform'" class="w-5 h-5" />
                        <IconPlusOutline v-else class="w-5 h-5 text-gray-500 dark:text-gray-400" />
                    </div>
                    <p class="af-passkey-add-card-title font-medium text-gray-700 dark:text-gray-300 text-sm">{{$t('Add cross-device')}}</p>
                    <p class="af-passkey-add-card-subtitle text-xs text-gray-400 dark:text-gray-500 text-center">{{$t('Use phone or security key')}}</p>
                </div>
            </template>
        </div>

        <div class="af-passkeys-info mt-6 flex items-center gap-2 px-4 py-3 bg-blue-50 w-full md:w-fit dark:bg-blue-900/20 border border-blue-100 dark:border-blue-800 rounded-xl text-sm text-blue-700 dark:text-blue-300">
            <IconInfoCircleOutline class="af-passkeys-info-icon w-4 h-4 shrink-0" />
            <span class="af-passkeys-info-text">{{$t('Passkeys are a more secure alternative to passwords. They use your device\'s biometrics or PIN and are resistant to phishing attacks.')}}</span>
        </div>

    </div>
</template>

<script setup lang="ts">
    import { callAdminForthApi } from '@/utils';
    import adminforth, { useAdminforth } from '@/adminforth';
    import { onMounted, ref, Ref } from 'vue';
    import { useI18n } from 'vue-i18n';
    import { Dialog, Tooltip, Spinner, Input } from '@/afcl';
    import { IconTrashBinSolid, IconPenSolid, IconPlusOutline, IconInfoCircleOutline } from '@iconify-prerendered/vue-flowbite';
    import dayjs from 'dayjs';
    import utc from 'dayjs/plugin/utc';
    import timezone from 'dayjs/plugin/timezone';
    import { useCoreStore } from '@/stores/core';

    const { t } = useI18n();
    dayjs.extend(utc);
    dayjs.extend(timezone);
    const coreStore = useCoreStore();

    interface Passkey {
        id: string;
        name: string;
        light_icon: string;
        dark_icon: string;
        last_used_at: string | null;
    }
    const passkeys = ref<Passkey[]>([]);
    const isPasskeySupported = ref(false);
    const passkeysNewName = ref('');
    const addPasskeyMode: Ref<'platform' | 'cross-platform'> = ref('platform');
    const authenticatorAttachment = ref<'platform' | 'cross-platform' | 'both'>('platform');
    const isInitialFinished = ref(false);
    const isFetchingPasskey = ref(false);

    onMounted(async () => {
        await getPasskeys();
        await checkPlatformSupport();
        if (authenticatorAttachment.value === 'cross-platform') {
            addPasskeyMode.value = 'cross-platform';
        }
        isInitialFinished.value = true;
    });

    function addLocalPasskey() {
        addPasskeyMode.value = 'platform';
        startAddPasskey();
    }

    function addCrossDevicePasskey() {
        addPasskeyMode.value = 'cross-platform';
        startAddPasskey();
    }

    async function startAddPasskey() {
        isFetchingPasskey.value = true;
        try {
            const confirmationResult = await window.adminforthTwoFaModal
                .get2FaConfirmationResult(t('To add passkey first verify yourself'));

            if (!confirmationResult) return;

            const { options, error } = await requestPasskeyChallenge(confirmationResult);
            if (!options) {
                adminforth.alert({ message: error ?? t('Verification failed.'), variant: 'warning' });
                return;
            }

            await finishAddPasskey(options);
        } catch {
            // user cancelled 2FA dialog
        } finally {
            isFetchingPasskey.value = false;
        }
    }

    async function finishAddPasskey(options: PublicKeyCredentialCreationOptions) {
        const credential = await createWebAuthnCredential(options);
        if (!credential) return;
        await registerPasskey(credential);
    }

    async function getPasskeys() {
        try {
            const response = await callAdminForthApi({
                path: '/plugin/passkeys/getPasskeys',
                method: 'GET',
            });
            passkeys.value = response.data;
            authenticatorAttachment.value = response.authenticatorAttachment;
        } catch (error) {
            console.error(t('Error fetching passkeys:'), error);
            if (coreStore.adminUser?.username) {
                adminforth.alert({ message: t('Error fetching passkeys.'), variant: 'warning' });
            }
        }
    }

    type ConfirmationResult = { mode: 'totp'; result: string } | { mode: 'passkey'; result: Record<string, any> };

    async function requestPasskeyChallenge(confirmationResult: ConfirmationResult) {
        try {
            const response = await callAdminForthApi({
                path: '/plugin/passkeys/registerPasskeyRequest',
                method: 'POST',
                body: { mode: addPasskeyMode.value, confirmationResult },
            });
            if (!response.ok) return { error: response.error ?? t('Verification failed') };
            const options = PublicKeyCredential.parseCreationOptionsFromJSON(response.data);
            return { options, challengeId: response.challengeId };
        } catch (error) {
            console.error(t('Error requesting passkey challenge:', error));
            return { error: t('Failed to request passkey challenge' )};
        }
    }

    async function createWebAuthnCredential(options: PublicKeyCredentialCreationOptions) {
        try {
            const credential = await navigator.credentials.create({ publicKey: options });
            return JSON.stringify((credential as PublicKeyCredential).toJSON());
        } catch (error) {
            console.error(t('Error creating WebAuthn credential:', error));
            adminforth.alert({ message: t('Error creating passkey.'), variant: 'warning' });
            return null;
        }
    }

    async function registerPasskey(credential: string) {
        try {
            const res = await callAdminForthApi({
                path: '/plugin/passkeys/finishRegisteringPasskey',
                method: 'POST',
                body: { credential, origin: window.location.origin },
            });
            if (res.ok) {
                adminforth.alert({ message: t('Passkey registered successfully!'), variant: 'success' });
                getPasskeys();
            } else {
                adminforth.alert({ message: t('Error registering passkey.'), variant: 'warning' });
            }
        } catch (error) {
            console.error(t('Error registering passkey:', error));
        }
    }

    async function confirmAndDelete(passkeyId: string) {
        const { confirm } = useAdminforth();
        const confirmed = await confirm({
            title: t('Remove passkey'),
            message: t('Are you sure you want to remove this passkey?'),
            yes: t('Remove'),
            no: t('Cancel'),
        });
        if (confirmed) deletePasskey(passkeyId);
    }

    async function deletePasskey(passkeyId: string) {
        try {
            const response = await callAdminForthApi({
                path: '/plugin/passkeys/deletePasskey',
                method: 'DELETE',
                body: { passkeyId },
            });
            if (response.ok) {
                adminforth.alert({ message: t('Passkey deleted successfully!'), variant: 'success' });
                getPasskeys();
            } else {
                console.error(t('Error deleting passkey:', response?.error));
                adminforth.alert({ message: t('Error deleting passkey.'), variant: 'warning' });
            }
        } catch (error) {
            console.error(t('Error deleting passkey:', error));
            adminforth.alert({ message: t('Error deleting passkey.'), variant: 'warning' });
        }
    }

    async function renamePasskey(passkeyId: string, name: string) {
        try {
            const response = await callAdminForthApi({
                path: '/plugin/passkeys/renamePasskey',
                method: 'POST',
                body: { passkeyId, newName: name },
            });
            if (response.ok) {
                adminforth.alert({ message: t('Passkey updated successfully!'), variant: 'success' });
                getPasskeys();
            } else {
                console.error(t('Error updating passkey:', response.error));
                adminforth.alert({ message: t('Error updating passkey.'), variant: 'warning' });
            }
        } catch (error) {
            console.error(t('Error updating passkey:', error));
            adminforth.alert({ message: t('Error updating passkey.'), variant: 'warning' });
        }
    }

    async function checkPlatformSupport() {
        if (!window.PublicKeyCredential
            || !PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable
            || !PublicKeyCredential.isConditionalMediationAvailable) {
            isPasskeySupported.value = false;
            addPasskeyMode.value = 'cross-platform';
            return;
        }
        const [platformOk, conditionalOk] = await Promise.all([
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
            PublicKeyCredential.isConditionalMediationAvailable(),
        ]);
        isPasskeySupported.value = platformOk && conditionalOk;
        if (!isPasskeySupported.value) {
            addPasskeyMode.value = 'cross-platform';
        }
    }

    function formatDateTime(date: string) {
        if (!date) return '';
        const fmt = `${coreStore.config?.datesFormat} ${coreStore.config?.timeFormat}` || 'YYYY-MM-DD HH:mm:ss';
        return dayjs.utc(date).local().format(fmt);
    }
</script>

<style>
 /* Scoped styles for dialog buttons, because there is no different way to style them */
 .dialog-delete-button.dialog-delete-button {
    background-color: rgb(179, 27, 27);
    color: white;
    border: 1px solid rgb(153, 27, 27);
 }
 .dialog-delete-button.dialog-delete-button:hover { background-color: rgb(153, 27, 27); }
 .dialog-delete-button.dialog-delete-button:active { background-color: rgb(127, 20, 20); }

 .dark .dialog-delete-button.dialog-delete-button { background-color: rgb(220, 38, 38); color: white; }
 .dark .dialog-delete-button.dialog-delete-button:hover { background-color: rgb(185, 28, 28); }
 .dark .dialog-delete-button.dialog-delete-button:active { background-color: rgb(153, 27, 27); }
</style>
