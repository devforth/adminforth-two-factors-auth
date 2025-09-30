import { AdminUser } from "adminforth";

export type PluginOptions = {

    /**
     * Name of the field in the auth resource which will store 2FA secret.
     *
     * Resource mandatory should have one columns which defined {@link AdminForthResourceColumn} which
     * name should be equal to the value .
     */
    twoFaSecretFieldName: string;

    /**
     * Not-negative optional time step window for 2FA. This value means that the user will be able to enter the old code
     * for the next 30 seconds after the new code was generated.
     */
    timeStepWindow?: number;

    customBrendPrefix?: string;

    /**
     * Passkeys (WebAuthn) configuration.
     */
    passkeys?: {
        credentialResourceID: string,
        credentialIdFieldName: string,
        credentialMetaFieldName: string,
        credentialUserIdFieldName: string,
        /**
         *  Period between showing alert suggesting to set up Passkeys if not set up yet.
         */
        suggestionPeriod?: string; // e.g. '30d', '12h', '15m'. Default is '5d'
        /**
         *  Passkeys settings for WebAuthn API.
         */
        settings: {
            /**
             * The origin that you expect the authentication to come from. (e.g. https://example.com or http://localhost:3000)
             */
            expectedOrigin: string;
            rp?: {
                /**
                 * The Relying Party name.
                 */
                name?: string;
                /**
                 * The Relying Party ID. A domain or subdomain (e.g. example.com or login.example.com).
                 */
                id?: string;
            },
            user: {
                /**
                 * Field in users resource, that user will recognize as unique user ID.(e.g. email or username)
                 */
                nameField: string;
                /**
                 * Field in users resource, that user will recognize as display name.(e.g. full name)
                 */
                displayNameField?: string;
            },
            authenticatorSelection?: {
                /**
                 * The preferred authenticator attachment. It can be either "platform", "cross-platform" or "both".
                 * Default to "platform".
                 */
                authenticatorAttachment?: 'platform' | 'cross-platform' | 'both';
                /**
                 * Set it to a boolean true. A discoverable credential (resident key) 
                 * stores user information to the passkey and lets users select the account upon authentication.
                 * Default to "True".
                 */
                requireResidentKey?: boolean;
                /**
                 * Indicates whether a user verification using the device screen lock is "required" or "discouraged". 
                 * The default is "required".
                 */
                userVerification?: 'required' | 'discouraged';
            }
        };
    };

    /**
     * Optional function to filter users to apply 2FA.
     * Should return true if 2FA should be applied to the user and false if AdminForth should not challenge the user with 2FA.
     * @param adminUser 
     * @returns true if 2FA should be applied to the user and false if AdminForth should not challenge the user with 2FA.
     */
    usersFilterToApply?: (adminUser: AdminUser) => boolean;

    /**
     * Optional function to allow users to skip 2FA setup.
     * Should return true if the user should be allowed to skip the 2FA setup and false if AdminForth should require the user to set up 2FA.
     * @param adminUser 
     * @returns true if the user should be allowed to skip the 2FA setup and false if AdminForth should require the user to set up 2FA.
     */
    usersFilterToAllowSkipSetup?: (adminUser: AdminUser) => boolean;
}