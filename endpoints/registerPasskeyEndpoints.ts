import type { IHttpServer } from "adminforth";

export function registerPasskeyEndpoints(server: IHttpServer, handlers: any): void {
  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/registrationOptions`,
    noAuth: false,
    handler: async ({ body, adminUser, response, cookies, headers }) =>
      handlers.createRegistrationOptions({ body, adminUser, response, cookies, headers }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/finishRegistration`,
    noAuth: false,
    handler: async ({ body, adminUser, cookies }) => handlers.finishRegistration({ body, adminUser, cookies }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/loginOptions`,
    noAuth: true,
    handler: async ({ response, headers }) => handlers.createLoginOptions({ response, headers }),
  });

  server.endpoint({
    method: 'GET',
    path: `/plugin/passkeys/getPasskeys`,
    noAuth: false,
    handler: async ({ adminUser }) => handlers.getPasskeys({ adminUser }),
  });

  server.endpoint({
    method: 'DELETE',
    path: `/plugin/passkeys/deletePasskey`,
    noAuth: false,
    handler: async ({ body, adminUser }) => handlers.deletePasskey({ body, adminUser }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/renamePasskey`,
    noAuth: false,
    handler: async ({ body, adminUser }) => handlers.renamePasskey({ body, adminUser }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/checkIfUserHasPasskeys`,
    noAuth: true,
    handler: async ({ cookies }) => handlers.checkIfUserHasPasskeys({ cookies }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/resolveVerifyAuto`,
    noAuth: false,
    handler: async ({ body, adminUser, response, cookies, headers }) =>
      handlers.resolveVerifyAuto({ body, adminUser, response, cookies, headers }),
  });
}
