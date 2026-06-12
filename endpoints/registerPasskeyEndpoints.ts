import type { IHttpServer } from "adminforth";

export function registerPasskeyEndpoints(server: IHttpServer, handlers: any): void {
  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/registerPasskeyRequest`,
    noAuth: false,
    handler: async ({ body, adminUser, response, cookies, headers }) =>
      handlers.registerPasskeyRequest({ body, adminUser, response, cookies, headers }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/finishRegisteringPasskey`,
    noAuth: false,
    handler: async ({ body, adminUser, cookies }) => handlers.finishRegisteringPasskey({ body, adminUser, cookies }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/signInRequest`,
    noAuth: true,
    handler: async ({ response }) => handlers.createSignInRequest({ response }),
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
