<template>
    <div class="text-3xl text-lightBreadcrumbsText dark:text-darkBreadcrumbsText font-semibold max-w-2xl mr-6 flex-col justify-center items-center">
        <p class="flex items-start justify-start leading-none">Passkeys</p>
        <div class="flex flex-col items-end">
            <Table
            class="mt-4 w-full"
                :columns="[
                    { label: 'Passkey name', fieldName: 'name' },
                    { label: 'Last used', fieldName: 'last_used_at' },
                    { label: 'Actions', fieldName: 'actions'}
                ]"
                :data="passkeys"
            >
            <template #cell:actions="{item}">
                <div class="flex items-center justify-start space-x-2">
                    <Dialog 
                        class="w-96"
                        :buttons="[
                            { label: 'Save', onclick: (dialog) => { renamePasskey(item.id, passkeysNewName); dialog.hide(); } },
                            { label: 'Cancel', options: {class: 'bg-white focus:!ring-gray-200 !text-gray-900 hover:!bg-gray-200 dark:!bg-gray-800 dark:!text-gray-300 dark:hover:!bg-gray-700 dark:border-gray-900 dark:hover:!border-gray-800 dark:focus:!ring-gray-800'}, onclick: (dialog) => {passkeysNewName = ''; dialog.hide();} },
                        ]"
                        header="Edit Passkey"
                    >
                        <template #trigger>
                            <Tooltip>
                                <div 
                                    @click="passkeysNewName = ''"
                                    class="w-7 h-7 flex items-center justify-center rounded-md text-blue-500 hover:text-blue-700 cursor-pointer"
                                >
                                    <IconPenSolid class="w-5 h-5" />
                                </div>

                                <template #tooltip>
                                    Rename passkey
                                </template>
                            </Tooltip>
                        </template>
                        <div>
                            <p>Enter new passkey name:</p>
                            <input 
                                v-model="passkeysNewName" 
                                type="text" 
                                class="w-full mt-2 p-2 border rounded-md dark:bg-gray-700 dark:border-gray-600 dark:focus:ring-gray-500 "
                                placeholder="Enter new passkey name"
                            />
                        </div>
                    </Dialog>
                    <Dialog 
                        class="w-96"
                        :buttons="[
                            { label: 'Delete', options: {class: 'bg-red-700 !text-white hover:!bg-red-600 focus:ring-2 focus:ring-red-500 dark:!bg-red-700 dark:hover:!bg-red-600 dark:focus:ring-red-500 dark:!border-red-800'}, onclick: (dialog) => { deletePasskey(item.id); dialog.hide(); } },
                            { label: 'Cancel', options: {class: 'bg-white focus:!ring-gray-200 !text-gray-900 hover:!bg-gray-200 dark:!text-white dark:!bg-gray-700 dark:hover:!bg-gray-800 dark:!border-gray-600 dark:focus:!ring-gray-800'}, onclick: (dialog) => dialog.hide() },
                        ]"
                        header="Delete Passkey"
                    >
                        <template #trigger>
                            <Tooltip>
                                <div class="w-7 h-7 flex items-center justify-center rounded-md text-red-500 hover:text-red-700 cursor-pointer">
                                    <IconTrashBinSolid 
                                        class="w-5 h-5" 
                                    />
                                </div>
                                <template #tooltip>
                                    Delete passkey
                                </template>
                            </Tooltip>
                        </template>
                        <div>
                            <p>Are you sure you want to delete this passkey?</p>
                        </div>
                    </Dialog>
                </div>  
            </template>
            <template #cell:last_used_at="{item}">
                <span v-if="item.last_used_at">{{ formatDateTime(item.last_used_at) }}</span>
                <span v-else class="text-gray-400">Never</span>
            </template>
            </Table>
            <div class="flex space-x-4 mt-4" v-if="isInitialFinished">
                <ButtonGroup :solidColor="true" v-if="isFetchingPasskey === false">
                    <template #button:Profile>
                        <div class="flex px-4 py-2" @click="addPasskeyStartAction()">
                            <IconPlusOutline class="w-5 h-5 me-2"/>
                            <p>{{ addPasskeyMode === 'platform' ? 'Add Local Passkey' : 'Add External Passkey' }}</p>
                        </div>
                    </template>
                    <template #button:Dropdown v-if="authenticatorAttachment === 'both'">
                        <div id="dropdown-button" class="flex px-2 py-2" @click="isCardsVisible = !isCardsVisible">
                            <IconCaretDownSolid class="w-5 h-5"/>
                        </div>
                    </template>
                </ButtonGroup>
                <p v-else class="flex items-center justify-center gap-2 text-base">Processing <Spinner class="w-4 h-4 inline-block" /></p>
            </div> 
            <div v-if="isCardsVisible" id="cards-container" class="w-80 mt-2 border-gray-400 p-2 bg-white rounded-lg shadow-md flex flex-col space-y-2">
                <div v-if="isPasskeySupported" class="flex justify-between gap-4" :class="!isPasskeySupported ? 'opacity-50 pointer-events-none' : ''">
                    <div class="shrink-0 mt-1 w-4 h-4 z-10"><IconCheckOutline v-if="addPasskeyMode === 'platform'"/></div>
                    <Card
                        @click="addPasskeyMode = 'platform'; isCardsVisible = false;"
                        class="h-20"
                        title="Use this device"
                        size="sm"
                        description="Create a passkey using the built-in authenticator on this device."
                        hideBorder="true"
                    >
                    </Card>
                </div>
                <Tooltip v-else >
                    <div class="flex justify-between gap-4" :class="!isPasskeySupported ? 'opacity-50 pointer-events-none' : ''">
                        <div class="shrink-0 mt-1 w-4 h-4 z-10"><IconCheckOutline v-if="addPasskeyMode === 'platform'"/></div>
                        <Card
                            @click="addPasskeyMode = 'platform'; isCardsVisible = false;"
                            class="h-20"
                            title="Use this device"
                            size="sm"
                            description="Create a passkey using the built-in authenticator on this device."
                            hideBorder="true"
                        >
                        </Card>
                    </div>

                    <template #tooltip>
                        <p class="max-w-64">This browser or device is reporting partial passkey support.</p>
                        <p class="max-w-64"> To fix it try to install extention or change browser.</p>
                    </template>
                </Tooltip>
                <div class="border-t border-gray-300"></div>
                <div class="flex justify-between gap-4">
                    <div class="shrink-0 mt-1 w-4 h-4 z-10"><IconCheckOutline v-if="addPasskeyMode === 'cross-platform'"/></div>
                    <Card
                        @click="addPasskeyMode = 'cross-platform'; isCardsVisible = false;"
                        size="sm"
                        class="h-20"
                        title="Use a external device"
                        description="Create a passkey using a phone, tablet or an external security key."
                        hideBorder="true"
                    >
                    </Card>
                </div>
            </div>
        </div>
        <Dialog 
            ref="confirmDialog" 
            class="w-96" 
            :click-to-close-outside="false"   
            :buttons="[]"
        >
            <div class="flex flex-col">
                <button
                type="button"
                class="text-lightDialogCloseButton bg-transparent hover:bg-lightDialogCloseButtonHoverBackground hover:text-lightDialogCloseButtonHover rounded-lg text-sm w-8 h-8 ms-auto inline-flex justify-center items-center dark:text-darkDialogCloseButton dark:hover:bg-darkDialogCloseButtonHoverBackground dark:hover:text-darkDialogCloseButtonHover"
                @click="{ isFetchingPasskey = false; fetchedOptions = null; closeDialog(); }"
                >
                    <svg class="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
                        <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
                    </svg>
                    <span class="sr-only">Close dialog</span>
                </button>
                <div class="flex items-center justify-center space-y-4">
                    Now you can add a passkey. 
                </div>
                <Button class="mt-4" @click="addPasskeyFinishAction(fetchedOptions); closeDialog();">Add Passkey</Button>
            </div>
        </Dialog>
    </div>
</template>

<script setup lang="ts">
    import { Table } from '@/afcl'
    import { callAdminForthApi } from '@/utils';
    import adminforth from '@/adminforth';
    import { onMounted, ref, Ref, onBeforeUnmount } from 'vue';
    import { Card, Dialog, ButtonGroup, Tooltip, Spinner, Button } from '@/afcl'
    import { IconTrashBinSolid, IconPenSolid, IconPlusOutline, IconCaretDownSolid, IconCheckOutline } from '@iconify-prerendered/vue-flowbite';
    import dayjs from 'dayjs';
    import utc from 'dayjs/plugin/utc';
    import timezone from 'dayjs/plugin/timezone';
    import { useCoreStore } from '@/stores/core';
    import { useUserStore } from '@/stores/user'

    dayjs.extend(utc);
    dayjs.extend(timezone);
    const coreStore = useCoreStore();
    const userStore = useUserStore();
    const passkeys = ref([]);
    const isPasskeySupported = ref(false);
    const passkeysNewName = ref('');
    const isCardsVisible = ref(false);
    const addPasskeyMode: Ref<'platform' | 'cross-platform'> = ref('platform');
    const authenticatorAttachment = ref<'platform' | 'cross-platform' | 'both'>('platform');
    const isInitialFinished = ref(false);
    const isFetchingPasskey = ref(false);

    const confirmDialog = ref(null);

    const openDialog = () => {
        confirmDialog.value.open();
    }

    const closeDialog = () => {
        confirmDialog.value.close();
    }

    const fetchedOptions = ref(null);

    onMounted(async () => {
        if (userStore.isAuthorized === true ) {
            await getPasskeys();
            await checkForCompatibility();
            if (authenticatorAttachment.value === "cross-platform") {
                addPasskeyMode.value = 'cross-platform';
            }   
            isInitialFinished.value = true;
        }
    });

    onMounted(() => {
        document.addEventListener('click', handleClickOutside);
    });

    onBeforeUnmount(() => {
        document.removeEventListener('click', handleClickOutside);
    });

    function handleClickOutside(event: MouseEvent) {
        const cards = document.getElementById('cards-container');
        const dropdownButton = document.getElementById('dropdown-button');

        if (!cards?.contains(event.target as Node) && !dropdownButton?.contains(event.target as Node)) {
            isCardsVisible.value = false;
        }
    }

    async function addPasskeyStartAction() {
        isFetchingPasskey.value = true;
        let confirmationResult;
        try {
            confirmationResult = await window.adminforthTwoFaModal.get2FaConfirmationResult(undefined, "To add passkey first verify yourself");
        } catch (e) {
            isFetchingPasskey.value = false;
            return;
        }
        if (!confirmationResult) {
            isFetchingPasskey.value = false;
            return;
        }
        const { options } = await fetchInformationFromTheBackend(confirmationResult);
        if (!options ) {
            isFetchingPasskey.value = false;
            adminforth.alert({message: 'Verification failed.', variant: 'warning'});
            return;
        }
        fetchedOptions.value = options;
        openDialog();
    }

    async function addPasskeyFinishAction(options) {
        const creationResult = await callWebAuthn(options);
        if (!creationResult) {
            isFetchingPasskey.value = false;
            fetchedOptions.value = null;
            return;
        }
        fetchedOptions.value = null;
        finishRegisteringPasskey(creationResult);
        isFetchingPasskey.value = false;
    }

    async function getPasskeys() {
        try {
            const response = await callAdminForthApi({
                path: `/plugin/passkeys/getPasskeys`,
                method: 'GET',
            });
            passkeys.value = response.data;
            authenticatorAttachment.value = response.authenticatorAttachment;
        } catch (error) {
            console.error('Error fetching passkeys:', error);
            adminforth.alert({message: 'Error fetching passkeys.', variant: 'warning'});
        }
    }

    async function deletePasskey(passkeyId: string) {
        let response;
        try {
            response = await callAdminForthApi({
                path: `/plugin/passkeys/deletePasskey`,
                method: 'DELETE',
                body: {
                    passkeyId: passkeyId
                }
            })
        } catch (error) {
            console.error('Error deleting passkey:', error);
            adminforth.alert({message: 'Error deleting passkey.', variant: 'warning'});
        }
        if (response.ok === true) {
            adminforth.alert({message: 'Passkey deleted successfully!', variant: 'success'});
            getPasskeys();
        } else {
            console.error('Error deleting passkey:', response?.error);
            adminforth.alert({message: 'Error deleting passkey.', variant: 'warning'});
        }
    }

    async function renamePasskey(passkeyId: string, name: string) {
        let response;
        try {
            response = await callAdminForthApi({ 
                path: `/plugin/passkeys/renamePasskey`,
                method: 'POST',
                body: {
                    passkeyId: passkeyId,
                    newName: name
                }
             })
        } catch (error) {
            console.error('Error updating passkey:', error);
            adminforth.alert({message: 'Error updating passkey.', variant: 'warning'});
        }
        if (response.ok === true) {
            adminforth.alert({message: 'Passkey updated successfully!', variant: 'success'});
            getPasskeys();
        } else {
            console.error('Error updating passkey:', response.error);
            adminforth.alert({message: 'Error updating passkey.', variant: 'warning'});
        }
    }

    function checkForCompatibility() {
        if (window.PublicKeyCredential &&  
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&  
            PublicKeyCredential.isConditionalMediationAvailable) {  
        Promise.all([  
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),  
            PublicKeyCredential.isConditionalMediationAvailable(),  
        ]).then(results => {  
            if (results.every(r => r === true)) {  
                isPasskeySupported.value = true;
            } else {  
                isPasskeySupported.value = false;
                addPasskeyMode.value = 'cross-platform';
            }  
        });  
        }  
    } 
    
    async function fetchInformationFromTheBackend(confirmationResult) {
        let response;
        try {
            response = await callAdminForthApi({
                path: `/plugin/passkeys/registerPasskeyRequest`,
                method: 'POST',
                body: {
                    mode: addPasskeyMode.value,
                    confirmationResult: confirmationResult
                },
            });
        } catch (error) {
            console.error('Error fetching passkeys info:', error);
            return;
        }
        if (!response.ok) {
            return {};
        }
        const _options = response.data;
        const challengeId = response.challengeId;
        const options = PublicKeyCredential.parseCreationOptionsFromJSON(_options);
        return { options, challengeId };
    }

    async function callWebAuthn(options: any) {
        let credential;
        try {
            credential = await navigator.credentials.create({
                publicKey: options
            });
        } catch (error) {
            console.error('Error creating credential:', error);
            adminforth.alert({message: 'Error creating passkey.', variant: 'warning'});
            return;
        }
        const _result = (credential as PublicKeyCredential).toJSON();
        const result = JSON.stringify(_result);
        return result;
    }

    async function finishRegisteringPasskey(credential: any) {
        let res 
        try {
            res = await callAdminForthApi({
                path: `/plugin/passkeys/finishRegisteringPasskey`,
                method: 'POST',
                body: {
                    credential: credential,
                    origin: window.location.origin,
                },
            });
        } catch (error) {
            console.error('Error finishing registering passkey:', error);
            return;
        }
        if (res.ok === true) {
            adminforth.alert({message: 'Passkey registered successfully!', variant: 'success'});
            getPasskeys();
        } else {
            adminforth.alert({message: 'Error registering passkey.', variant: 'warning'});
        }
    }

    function formatDateTime(date: string) {
        if (!date) return '';
        return dayjs.utc(date).local().format(`${coreStore.config?.datesFormat} ${coreStore.config?.timeFormat}` || 'YYYY-MM-DD HH:mm:ss');
    }
</script>