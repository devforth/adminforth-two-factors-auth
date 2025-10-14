   import { callAdminForthApi } from '@/utils';

   export function handlePasskeyAlert(propSuggestionPeriod, router) {
        const currentDate = Date.now();
        window.localStorage.removeItem('suggestionPeriod');
        window.localStorage.setItem('suggestionPeriod', propSuggestionPeriod);
        let suggestionPeriod = window.localStorage.getItem('suggestionPeriod');
        let lastSuggestionDate = window.localStorage.getItem('lastSuggestionDate');
        let suggestPasskey = window.localStorage.getItem('suggestPasskey');
        if ( !lastSuggestionDate ) { 
        window.localStorage.setItem('lastSuggestionDate', currentDate.toString());
        lastSuggestionDate = window.localStorage.getItem('lastSuggestionDate');
        }
        if ( !suggestPasskey ) {
        window.localStorage.setItem('suggestPasskey', 'true');
        suggestPasskey = window.localStorage.getItem('suggestPasskey');
        }
        if ( currentDate - parseInt(lastSuggestionDate) > parseInt(suggestionPeriod) ) {
        suggestPasskey = window.localStorage.getItem('suggestPasskey');
        if (suggestPasskey !== 'true'){
            if ( suggestPasskey === 'false' || !suggestPasskey ) {
            window.localStorage.setItem('suggestPasskey', 'true');
            } else if ( suggestPasskey !== 'never' ) {
            window.localStorage.setItem('suggestPasskey', 'false');
            }
        }
        }
        suggestPasskey = window.localStorage.getItem('suggestPasskey');

        if ( suggestPasskey === 'true' ) {
        adminforth.alert({
            message: 'Do you want to add passkey?', 
            variant: 'info', 
            buttons: [
            { value: 'yes', label: 'Add passkey' },
            { value: 'later', label: 'Later' },
            { value: 'never', label: 'Never' },
            ],
            timeout: 'unlimited'
        }).then((value) => {
            switch (value) {
            case 'yes':
                router.push({ name: 'settings', params: { page: 'passkeys' } });
                break;
            case 'later':
                window.localStorage.setItem('suggestPasskey', 'false');
                break;
            case 'never':
                window.localStorage.setItem('suggestPasskey', 'never');
                break;
            default:
                window.localStorage.setItem('suggestPasskey', 'false');
                break;
            }
        });
        }
    }

    export async function getPasskey() {
    const { _options } = await createSignInRequest();
    let options;
    try {
      options = PublicKeyCredential.parseRequestOptionsFromJSON(_options);
    } catch (e) {
      console.error('Error parsing request options:', e);
      adminforth.alert({message: 'Error initiating passkey authentication.', variant: 'warning'});
      return;
    }
    const credential = await authenticate(options);
    if (!credential) {
      isFetchingPasskey.value = false;
      return;
    }
    const result = JSON.stringify(credential);
    const passkeyOptions = {
      response: result,
      origin: window.location.origin,
    };
    return passkeyOptions;
  }

  async function createSignInRequest() {
    let response;
    try {
      response = await callAdminForthApi({
        path: `/plugin/passkeys/signInRequest`,
        method: 'POST',
      });
    } catch (error) {
      console.error('Error creating sign-in request:', error);
      return;
    }
    if (response.ok === true) {
      return { _options: response.data, challengeId: response.challengeId };
    } else {
      adminforth.alert({message: 'Error creating sign-in request.', variant: 'warning'});
      codeError.value = 'Error creating sign-in request.';
    }
  }

  let controller = new AbortController();

  async function authenticate(options) {
    controller.abort();
    try {
      const abortController = new AbortController();
      const credential = await navigator.credentials.get({
        publicKey: options,
        signal: abortController.signal,
      });
      return credential;
    } catch (error) {
      console.error('Error during authentication:', error);
      // Handle specific concurrent/pending request error cases gracefully
      const name = (error && (error.name || error.constructor?.name)) || '';
      const message = (error && error.message) || '';
      if (name === 'AbortError') {
        // Aborted intentionally; no user-facing error needed
        return null;
      } else if (name === 'InvalidStateError' || name === 'OperationError' || /pending/i.test(message)) {
        adminforth.alert({ message: t('Another security prompt is already open. Please try again.'), variant: 'warning' });
        codeError.value = t('A previous passkey attempt was still pending. Please try again.');
        return null;
      } else if (name === 'NotAllowedError') {
        adminforth.alert({ message: `The operation either timed out or was not allowed`, variant: 'warning' });
        codeError.value = 'The operation either timed out or was not allowed.';
        return null;
      } else {
        adminforth.alert({message: `Error during authentication: ${error}`, variant: 'warning'});
        codeError.value = 'Error during authentication.';
        return null;
      }
    }
  }
