<template>
    <div class="text-3xl text-gray-900 font-semibold mt-2 w-full flex-col justify-center items-center">
        <p>Passkeys</p>
        <Table
        class="mr-12"
            :columns="[
                { label: 'Passkey name', fieldName: 'name' },
                { label: 'Last used', fieldName: 'lastUsed' },
                { label: 'Delete', fieldName: 'delete' },
            ]"
            :data="[
                { name: 'John', lastUsed: '2022-01-01', delete: 'Delete' },
                { name: 'Rick', lastUsed: '2022-01-02', delete: 'Delete' },
                { name: 'Alice', lastUsed: '2022-01-03', delete: 'Delete' },
                { name: 'Colin', lastUsed: '2022-01-04', delete: 'Delete' },
            ]"
        ></Table>
        <button
            class="text-md font-medium mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            @click="addPasskey"
        >
            Add Passkey
        </button>
    </div>
</template>

<script setup lang="ts">
    import { Table } from '@/afcl'
    import { callAdminForthApi } from '@/utils';
    import adminforth from '@/adminforth';

    async function addPasskey() {
        checkForCompatibility();
        const { options, newRecordId } = await fetchInformationFromTheBackend();
        const creationResult = await callWebAuthn(options);
        if (!creationResult) {
            return;
        }
        finishRegisteringPasskey(creationResult, newRecordId);
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
                //console.log("Platform authenticator is available");  
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
        const newRecordId = response.newRecordId;
        const options = PublicKeyCredential.parseCreationOptionsFromJSON(_options);
        return { options, newRecordId };
    }

    async function callWebAuthn(options: any) {
        let credential;
        try {
            credential = await navigator.credentials.create({
                publicKey: options
            });
        } catch (error) {
            adminforth.alert({message: 'Error creating credential. Probably already registered.', variant: 'warning'});
            return;
        }
        const _result = (credential as PublicKeyCredential).toJSON();
        const result = JSON.stringify(_result);
        return result;
    }

    async function finishRegisteringPasskey(credential: any, newRecordId: string) {
        let res 
        try {
        res = await callAdminForthApi({
            path: `/plugin/passkeys/finishRegisteringPasskey`,
            method: 'POST',
            body: {
                credential: credential,
                origin: window.location.origin,
                newRecordId: newRecordId
            },
        });
        } catch (error) {
            console.error('Error finishing registering passkey:', error);
            return;
        }
    }
</script>