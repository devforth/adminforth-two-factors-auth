<template>
    <div class="af-passkeys flex flex-col justify-center mr-6 md:mr-12">
        <h2 class="af-passkeys-title text-lg font-semibold tracking-tight text-lightCardTitle dark:text-darkCardTitle">{{$t('Passkeys')}}</h2>
        <p class="af-passkeys-subtitle mt-1 text-sm text-lightCardDescription dark:text-darkCardDescription"> {{$t('Manage your passwordless authentication methods')}} </p>

        <div class="af-passkeys-grid mt-6 flex flex-wrap gap-4">
            <Card
                v-for="item in passkeys"
                :key="item.id"
                size="md"
                class="af-passkey-card flex flex-col w-full h-42 lg:w-72"
            >
                <div class="af-passkey-card-header flex items-center gap-3 mb-3">
                    <div class="af-passkey-card-icon flex w-10 h-10 shrink-0 items-center justify-center rounded-lg bg-lightSecondaryDarken dark:bg-darkSecondaryLighten">
                        <img class="max-h-6 max-w-6" :src="coreStore.theme === 'light' ? item.light_icon : item.dark_icon" />
                    </div>
                    <div class="af-passkey-card-info flex-1 min-w-0">
                        <p class="af-passkey-card-name font-semibold text-lightDialogHeaderText dark:text-darkDialogHeaderText truncate" :title="item.name">{{ item.name }}</p>
                        <p class="af-passkey-card-type text-xs text-lightInputIconColor dark:text-darkInputIconColor">{{$t('Synced passkey')}}</p>
                    </div>
                    <span class="af-passkey-card-badge shrink-0 inline-flex items-center px-2 py-0.5 rounded-full border text-xs font-medium border-lightSuccessBorder bg-lightSuccessSoft text-lightSuccess dark:border-darkSuccessBorder dark:bg-darkSuccessSoft dark:text-darkSuccess">
                        {{$t('Active')}}
                    </span>
                </div>

                <div class="af-passkey-card-last-used text-xs text-lightInputIconColor dark:text-darkInputIconColor mb-4">
                    <span class="af-passkey-card-last-used-label font-medium text-lightInputText dark:text-darkInputText">{{$t('Last used')}}:</span>
                    <span v-if="item.last_used_at" class="af-passkey-card-last-used-date ml-1">{{ formatDateTime(item.last_used_at) }}</span>
                    <span v-else class="af-passkey-card-last-used-never ml-1 italic">{{$t('Never')}}</span>
                </div>

                <div class="af-passkey-card-actions grid grid-cols-2 gap-2 mt-auto">
                    <Dialog
                        class="edit-passkey-confirmation-dialog w-96"
                        :buttons="[
                            { label: t('Cancel'), options: { class: 'dialog-cancel-button w-full', variant: 'secondary' }, onclick: (dialog) => { passkeysNewName = ''; dialog.hide(); } },
                            { label: t('Save'), options: { class: 'dialog-save-button w-full' }, onclick: (dialog) => { renamePasskey(item.id, passkeysNewName); dialog.hide(); } },
                        ]"
                        :header="t('Edit Passkey')"
                    >
                        <template #trigger>
                            <Button
                                type="button"
                                variant="secondary"
                                @click="passkeysNewName = ''"
                                class="af-passkey-btn-rename w-full"
                            >
                                <IconPencil class="w-4 h-4" />
                                {{$t('Rename')}}
                            </Button>
                        </template>
                        <div class="flex flex-col gap-2">
                            <label class="text-sm font-medium">{{$t('Current name:')}}</label>
                            <p class="font-medium text-sm text-lightInputText dark:text-darkInputText pb-2 truncate" :title="item.name">{{ item.name }}</p>
                            <label class="text-sm font-medium">{{$t('Enter new passkey name:')}}</label>
                            <Input
                                v-model="passkeysNewName"
                                type="text"
                                class="w-full"
                                :placeholder="$t('New name')"
                            />
                        </div>
                    </Dialog>

                    <Button
                        type="button"
                        variant="danger-soft"
                        @click="confirmAndDelete(item.id)"
                        class="af-passkey-btn-remove w-full"
                    >
                        <IconTrash2 class="w-4 h-4" />
                        {{$t('Remove')}}
                    </Button>
                </div>
            </Card>

            <template v-if="isInitialFinished">
                <Tooltip v-if="!isPasskeySupported && (authenticatorAttachment === 'platform' || authenticatorAttachment === 'both')">
                    <div class="af-passkey-add-card af-passkey-add-local flex flex-col items-center justify-center gap-2 p-4 rounded-lg border border-dashed border-lightInputBorder dark:border-darkInputBorder w-full lg:w-72 min-h-36 opacity-50 cursor-not-allowed">
                        <div class="af-passkey-add-card-icon w-10 h-10 flex items-center justify-center rounded-full bg-lightPrimary/10 text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">
                            <IconPlus class="w-5 h-5" />
                        </div>
                        <p class="af-passkey-add-card-title font-medium text-lightInputText dark:text-darkInputText text-sm">{{$t('Add local passkey')}}</p>
                        <p class="af-passkey-add-card-subtitle text-xs text-lightInputIconColor dark:text-darkInputIconColor text-center">{{$t('Register this device')}}</p>
                    </div>
                    <template #tooltip>
                        <p class="max-w-64">{{$t('This browser or device is reporting partial passkey support.')}}</p>
                        <p class="max-w-64">{{$t('To fix it try to install extention or change browser.')}}</p>
                    </template>
                </Tooltip>

                <button
                    v-else-if="authenticatorAttachment === 'platform' || authenticatorAttachment === 'both'"
                    type="button"
                    :disabled="isFetchingPasskey"
                    @click="addLocalPasskey"
                    class="af-passkey-add-card af-passkey-add-local flex flex-col items-center justify-center gap-2 p-4 rounded-lg border border-dashed border-lightInputBorder dark:border-darkInputBorder enabled:hover:border-lightPrimary enabled:hover:bg-lightPrimary/5 dark:enabled:hover:border-darkPrimary dark:enabled:hover:bg-darkPrimary/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors w-full lg:w-72 min-h-36"
                >
                    <span class="af-passkey-add-card-icon w-10 h-10 flex items-center justify-center rounded-full bg-lightPrimary/10 text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">
                        <Spinner v-if="isFetchingPasskey && addPasskeyMode === 'platform'" class="w-5 h-5" />
                        <IconPlus v-else class="w-5 h-5" />
                    </span>
                    <span class="af-passkey-add-card-title font-medium text-lightInputText dark:text-darkInputText text-sm">{{$t('Add local passkey')}}</span>
                    <span class="af-passkey-add-card-subtitle text-xs text-lightInputIconColor dark:text-darkInputIconColor text-center">{{$t('Register this device')}}</span>
                </button>

                <button
                    v-if="authenticatorAttachment === 'cross-platform' || authenticatorAttachment === 'both'"
                    type="button"
                    :disabled="isFetchingPasskey"
                    @click="addCrossDevicePasskey"
                    class="af-passkey-add-card af-passkey-add-cross flex flex-col items-center justify-center gap-2 p-4 rounded-lg border border-dashed border-lightInputBorder dark:border-darkInputBorder enabled:hover:border-lightPrimary enabled:hover:bg-lightPrimary/5 dark:enabled:hover:border-darkPrimary dark:enabled:hover:bg-darkPrimary/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors w-full lg:w-72 min-h-36"
                >
                    <span class="af-passkey-add-card-icon w-10 h-10 flex items-center justify-center rounded-full bg-lightPrimary/10 text-lightPrimary dark:bg-darkPrimary/20 dark:text-darkPrimary">
                        <Spinner v-if="isFetchingPasskey && addPasskeyMode === 'cross-platform'" class="w-5 h-5" />
                        <IconPlus v-else class="w-5 h-5" />
                    </span>
                    <span class="af-passkey-add-card-title font-medium text-lightInputText dark:text-darkInputText text-sm">{{$t('Add cross-device')}}</span>
                    <span class="af-passkey-add-card-subtitle text-xs text-lightInputIconColor dark:text-darkInputIconColor text-center">{{$t('Use phone or security key')}}</span>
                </button>
            </template>
        </div>

        <TwoFaHint class="af-passkeys-info mt-6 w-full md:w-fit">
            <template #icon><IconInfo class="af-passkeys-info-icon w-5 h-5" /></template>
            {{$t('Passkeys are a more secure alternative to passwords. They use your device\'s biometrics or PIN and are resistant to phishing attacks.')}}
        </TwoFaHint>

    </div>
</template>

<script setup lang="ts">
    import { callAdminForthApi, formatDateTime } from '@/utils';
    import adminforth, { useAdminforth } from '@/adminforth';
    import { onMounted, ref, Ref } from 'vue';
    import { useI18n } from 'vue-i18n';
    import { Button, Card, Dialog, Tooltip, Spinner, Input } from '@/afcl';
    import { IconTrash2, IconPencil, IconPlus, IconInfo } from '@iconify-prerendered/vue-lucide';
    import TwoFaHint from './TwoFaHint.vue';
    import { useCoreStore } from '@/stores/core';
    import { useTwoFactorsAuth, type TwoFaConfirmationResult } from './use2faApi';

    const { t } = useI18n();
    const coreStore = useCoreStore();
    const twoFactorsAuth = useTwoFactorsAuth();

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
            const confirmationResult = await twoFactorsAuth.get2FaConfirmationResult(
                t('To add passkey first verify yourself')
            );

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
            console.error('Error fetching passkeys:', error);
            if (coreStore.adminUser?.username) {
                adminforth.alert({ message: t('Error fetching passkeys.'), variant: 'warning' });
            }
        }
    }

    async function requestPasskeyChallenge(confirmationResult: TwoFaConfirmationResult) {
        try {
            const response = await callAdminForthApi({
                path: '/plugin/passkeys/registrationOptions',
                method: 'POST',
                body: { mode: addPasskeyMode.value, confirmationResult },
            });
            if (!response.ok) return { error: response.error ?? t('Verification failed') };
            console.log('Passkey challenge response:', response.data);
            const options = PublicKeyCredential.parseCreationOptionsFromJSON(response.data);
            console.log('Parsed PublicKeyCredentialCreationOptions:', options);
            return { options, challengeId: response.challengeId };
        } catch (error) {
            console.error('Error requesting passkey challenge:', error);
            return { error: t('Failed to request passkey challenge' )};
        }
    }

    async function createWebAuthnCredential(options: PublicKeyCredentialCreationOptions) {
        try {
            const credential = await navigator.credentials.create({ publicKey: options });
            return JSON.stringify((credential as PublicKeyCredential).toJSON());
        } catch (error) {
            console.error('Error creating WebAuthn credential:', error);

            let message = t('Failed to create passkey.');

            if (error?.name === 'InvalidStateError') {
                message = t('A passkey for this account already exists on this device.');
            }

            if (error?.name === 'NotAllowedError') {
                message = t('Passkey creation was cancelled.');
            }

            if (error?.name === 'NotSupportedError') {
                message = t('Passkeys are not supported on this device or browser.');
            }

            adminforth.alert({ message, variant: 'danger'});

            return null;
        }
    }

    async function registerPasskey(credential: string) {
        try {
            const res = await callAdminForthApi({
                path: '/plugin/passkeys/finishRegistration',
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
            console.error('Error registering passkey:', error);
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
                console.error('Error deleting passkey:', response?.error);
                adminforth.alert({ message: t('Error deleting passkey.'), variant: 'warning' });
            }
        } catch (error) {
            console.error('Error deleting passkey:', error);
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
                console.error('Error updating passkey:', response.error);
                adminforth.alert({ message: t('Error updating passkey.'), variant: 'warning' });
            }
        } catch (error) {
            console.error('Error updating passkey:', error);
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
</script>
