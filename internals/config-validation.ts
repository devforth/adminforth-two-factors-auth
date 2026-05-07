import { suggestIfTypo } from "adminforth";

export function validatePluginConfig(plugin: any, adminforth: any): void {
  if (plugin.options.passkeys) {

    const adminForthResources = [];
    for (const res of adminforth.config.resources) {
      adminForthResources.push(res.resourceId);
    }
    if (!plugin.options.passkeys.credentialResourceID) {
      throw new Error('Passkeys credentialResourceID is required');
    }
    if ( !(adminForthResources.includes(plugin.options.passkeys.credentialResourceID)) ) {
      throw new Error('Passkeys credentialResourceID is not valid');
    }
    if (!plugin.options.passkeys.credentialIdFieldName) {
      throw new Error('Passkeys credentialIdFieldName is required');
    }

    if (!plugin.options.passkeys.keyValueAdapter) {
      throw new Error('Passkeys keyValueAdapter is required');
    }

    const credentialResource = adminforth.config.resources.find(r => r.resourceId === plugin.options.passkeys.credentialResourceID);
    const credentialIDField = credentialResource.columns.find(c => c.name === plugin.options.passkeys.credentialIdFieldName);
    if ( !credentialIDField ) {
      const similar = suggestIfTypo(credentialResource.columns.map(c => c.name), plugin.options.passkeys.credentialIdFieldName);
      throw new Error(
        `Passkeys credentialIdFieldName '${plugin.options.passkeys.credentialIdFieldName}' not found in resource '${plugin.options.passkeys.credentialResourceID}'. ${
          similar ? `Did you mean '${similar}'?` : ''
        }`
      );
    }
    credentialIDField.backendOnly = true;

    if (!plugin.options.passkeys.credentialMetaFieldName) {
      throw new Error('Passkeys credentialMetaFieldName is required');
    }

    const metaResource = adminforth.config.resources.find(r => r.resourceId === plugin.options.passkeys.credentialMetaFieldName);
    const metaField = credentialResource.columns.find(c => c.name === plugin.options.passkeys.credentialMetaFieldName);
    if ( !metaField ) {
      const similar = suggestIfTypo(metaResource.columns.map(c => c.name), plugin.options.passkeys.credentialMetaFieldName);
      throw new Error(
        `Passkeys credentialMetaFieldName '${plugin.options.passkeys.credentialMetaFieldName}' not found in resource '${plugin.options.passkeys.credentialMetaFieldName}'. ${
          similar ? `Did you mean '${similar}'?` : ''
        }`
      );
    }
    metaField.backendOnly = true;


    if (!plugin.options.passkeys.credentialUserIdFieldName) {
      throw new Error('Passkeys credentialUserIdFieldName is required');
    }
    if (!plugin.options.passkeys.settings) {
      throw new Error('Passkeys settings are required when passkeys option is enabled');
    }
    if (!plugin.options.passkeys.settings.expectedOrigin) {
      throw new Error('Passkeys settings.expectedOrigin is required');
    }
    const origin = new URL( plugin.options.passkeys.settings.expectedOrigin ).origin;
    if ( origin !== plugin.options.passkeys.settings.expectedOrigin ) {
      throw new Error('Passkeys settings.expectedOrigin is not valid');
    }
    if (plugin.options.passkeys.settings.authenticatorSelection) {
      if (plugin.options.passkeys.settings.authenticatorSelection.authenticatorAttachment) {
        if ( !['platform', 'cross-platform', 'both'].includes(plugin.options.passkeys.settings.authenticatorSelection.authenticatorAttachment) ) {
          throw new Error('Passkeys settings.authenticatorSelection.authenticatorAttachment is not valid');
        }
      }
      if (plugin.options.passkeys.settings.authenticatorSelection.userVerification) {
        if ( !['required', 'discouraged'].includes(plugin.options.passkeys.settings.authenticatorSelection.userVerification) ) {
          throw new Error('Passkeys settings.authenticatorSelection.userVerification is not valid');
        }
      }
    }

    if (!plugin.options.passkeys.settings.user) {
      throw new Error('Passkeys settings.user is required');
    }
    if (!plugin.options.passkeys.settings.user.nameField) {
      throw new Error('Passkeys settings.user.nameField is required');
    }
  }
}
