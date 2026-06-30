import type { IHttpServer } from "adminforth";
import {
  parseBody,
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
    handler: async ({ body, adminUser, response, cookies, headers }) => {
      if (!parseBody(registrationOptionsBodySchema, body, response)) return;
      return handlers.createRegistrationOptions({ body, adminUser, response, cookies, headers });
    },
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/finishRegistration`,
    noAuth: false,
    handler: async ({ body, adminUser, cookies, response }) => {
      if (!parseBody(finishRegistrationBodySchema, body, response)) return;
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
    handler: async ({ body, adminUser, response }) => {
      if (!parseBody(deletePasskeyBodySchema, body, response)) return;
      return handlers.deletePasskey({ body, adminUser });
    },
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/passkeys/renamePasskey`,
    noAuth: false,
    handler: async ({ body, adminUser, response }) => {
      if (!parseBody(renamePasskeyBodySchema, body, response)) return;
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
    handler: async ({ body, adminUser, response, cookies, headers }) => {
      if (!parseBody(resolveVerifyAutoBodySchema, body, response)) return;
      return handlers.resolveVerifyAuto({ body, adminUser, response, cookies, headers });
    },
  });
}
