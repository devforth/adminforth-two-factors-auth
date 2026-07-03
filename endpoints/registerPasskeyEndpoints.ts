import type { IHttpServer } from "adminforth";
import {
  registrationOptionsBodySchema,
  finishRegistrationBodySchema,
  deletePasskeyBodySchema,
  renamePasskeyBodySchema,
  resolveVerifyAutoBodySchema,
} from "./validation.js";

export function registerPasskeyEndpoints(server: IHttpServer, handlers: any): void {
  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/registrationOptions`,
    noAuth: false,
    request_schema: registrationOptionsBodySchema,
    handler: async ({ body, adminUser, response, cookies, headers }) => {
      return handlers.createRegistrationOptions({ body, adminUser, response, cookies, headers });
    },
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/finishRegistration`,
    noAuth: false,
    request_schema: finishRegistrationBodySchema,
    handler: async ({ body, adminUser, cookies }) => {
      return handlers.finishRegistration({ body, adminUser, cookies });
    },
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
    request_schema: deletePasskeyBodySchema,
    handler: async ({ body, adminUser }) => {
      return handlers.deletePasskey({ body, adminUser });
    },
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/renamePasskey`,
    noAuth: false,
    request_schema: renamePasskeyBodySchema,
    handler: async ({ body, adminUser }) => {
      return handlers.renamePasskey({ body, adminUser });
    },
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
    request_schema: resolveVerifyAutoBodySchema,
    handler: async ({ body, adminUser, response, cookies, headers }) => {
      return handlers.resolveVerifyAuto({ body, adminUser, response, cookies, headers });
    },
  });
}
