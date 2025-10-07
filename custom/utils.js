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