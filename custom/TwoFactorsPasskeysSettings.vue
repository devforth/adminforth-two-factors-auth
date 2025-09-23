<template>
    <div class="text-3xl text-gray-900 font-semibold mt-2 w-full flex-col justify-center items-center">
        <p>Passkeys</p>
        <Table
        class="mt-4 max-w-2xl"
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
                        { label: 'Cancel', options: {class: 'bg-white !text-gray-900 hover:!bg-gray-200'}, onclick: (dialog) => {passkeysNewName = ''; dialog.hide();} },
                    ]"
                    header="Edit Passkey"
                >
                    <template #trigger>
                        <div 
                            @click="passkeysNewName = ''"
                            class="w-7 h-7 flex items-center justify-center hover:border rounded-md hover:shadow-md text-blue-500 hover:text-blue-700 cursor-pointer"
                        >
                            <IconPenSolid class="w-5 h-5" />
                        </div>
                    </template>
                    <div>
                        <p>Enter new passkey name:</p>
                        <input 
                            v-model="passkeysNewName" 
                            type="text" 
                            class="w-full mt-2 p-2 border rounded-md"
                            placeholder="Enter new passkey name"
                        />
                    </div>
                </Dialog>
                <Dialog 
                    class="w-96"
                    :buttons="[
                        { label: 'Delete', options: {class: 'bg-red-500 !text-white hover:!bg-red-900'}, onclick: (dialog) => { deletePasskey(item.id); dialog.hide(); } },
                        { label: 'Cancel', options: {class: 'bg-white !text-gray-900 hover:!bg-gray-200'}, onclick: (dialog) => dialog.hide() },
                    ]"
                    header="Delete Passkey"
                >
                    <template #trigger>
                        <div class="w-7 h-7 flex items-center justify-center hover:border rounded-md hover:shadow-md text-red-500 hover:text-red-700 cursor-pointer">
                            <IconTrashBinSolid 
                                class="w-5 h-5" 
                            />
                        </div>
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
        <div class="flex space-x-4 mt-4">
            <Button
                @click="addPasskey"
                :disabled="!isPasskeySupported"
            >
                Add Passkey
            </Button>
            <Button
                @click="checkMyPasskey"
                :disabled="!isPasskeySupported"
            >
                Check my passkey
            </Button>
        </div> 
    </div>
</template>

<script setup lang="ts">
    import { Table } from '@/afcl'
    import { callAdminForthApi } from '@/utils';
    import adminforth from '@/adminforth';
    import { onMounted, ref } from 'vue';
    import { Button, Dialog, Input } from '@/afcl'
    import { IconTrashBinSolid, IconPenSolid } from '@iconify-prerendered/vue-flowbite';
    import dayjs from 'dayjs';
    import utc from 'dayjs/plugin/utc';
    import timezone from 'dayjs/plugin/timezone';
    import { useCoreStore } from '@/stores/core';


    dayjs.extend(utc);
    dayjs.extend(timezone);
    const coreStore = useCoreStore();
    const passkeys = ref([]);
    const isPasskeySupported = ref(false);
    const passkeysNewName = ref('');

    onMounted(() => {
        getPasskeys();
        checkForCompatibility();
    });

    async function addPasskey() {
        const { options, challengeId } = await fetchInformationFromTheBackend();
        const creationResult = await callWebAuthn(options);
        if (!creationResult) {
            return;
        }
        finishRegisteringPasskey(creationResult, challengeId);
    }

    async function checkMyPasskey() {
        const { _options, challengeId } = await createSignInRequest();
        const options = PublicKeyCredential.parseRequestOptionsFromJSON(_options);
        const credential = await authenticate(options);
        const result = JSON.stringify(credential);
        const user = await authenticateBackend(result, challengeId);
        console.log("Authenticated user:", user);
    }

    async function getPasskeys() {
        try {
            const response = await callAdminForthApi({
                path: `/plugin/passkeys/getPasskeys`,
                method: 'GET',
            });
            passkeys.value = response.data;
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
                adminforth.alert({message: 'Passkeys are not supported on this device or browser.', variant: 'warning'});
                isPasskeySupported.value = false;
            }  
        });  
        }  
    } 
    
    async function fetchInformationFromTheBackend() {
        let response;
        try {
            response = await callAdminForthApi({
                path: `/plugin/passkeys/registerPasskeyRequest`,
                method: 'POST',
                body: {
                },
            });
        } catch (error) {
            console.error('Error fetching passkeys info:', error);
            return;
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

    async function finishRegisteringPasskey(credential: any, challengeId: string) {
        let res 
        try {
            res = await callAdminForthApi({
                path: `/plugin/passkeys/finishRegisteringPasskey`,
                method: 'POST',
                body: {
                    credential: credential,
                    origin: window.location.origin,
                    challengeId: challengeId,
                    passkeyName: navigator.userAgent
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

    async function createSignInRequest() {
        let response;
        try {
            response = await callAdminForthApi({
                path: `/plugin/passkeys/signInRequest`,
                method: 'GET',
            });
        } catch (error) {
            console.error('Error creating sign-in request:', error);
            return;
        }
        if (response.ok === true) {
            return { _options: response.data, challengeId: response.challengeId };
        } else {
            adminforth.alert({message: 'Error creating sign-in request.', variant: 'warning'});
        }
    }

    async function authenticate(options: any) {
        const abortController = new AbortController();
        const credential = await navigator.credentials.get({
            publicKey: options,
            signal: abortController.signal,
            mediation: 'required'
        });
        return credential;
    }

    async function authenticateBackend(response: any, challengeId: string) {
        let res;
        try {
            res = await callAdminForthApi({
                path: `/plugin/passkeys/signInResponse`,
                method: 'POST',
                body: {
                    response: response,
                    challengeId: challengeId,
                    origin: window.location.origin,
                }
            });
        } catch (error) {
            console.error('Error authenticating passkey:', error);
            return;
        }
        if (res) {
            if (res.ok === true) {
                adminforth.alert({message: 'Passkey authenticated successfully!', variant: 'success'});
                getPasskeys();
                return res;
            } else {
                console.error('Error authenticating passkey:', res.error);
                adminforth.alert({message: 'Error authenticating passkey.', variant: 'warning'});
            }
        }
    }

    function formatDateTime(date: string) {
        if (!date) return '';
        return dayjs.utc(date).local().format(`${coreStore.config?.datesFormat} ${coreStore.config?.timeFormat}` || 'YYYY-MM-DD HH:mm:ss');
    }
</script>