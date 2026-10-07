import type { IHttpServer } from "adminforth";
import {
  confirmLoginBodySchema,
  confirmLoginWithPasskeyBodySchema,
  verifyTotpBodySchema,
} from "./validation.js";

export function registerTwoFaEndpoints(server: IHttpServer, handlers: any): void {
  server.endpoint({
    method: 'POST',
    path: `/plugin/twofa/initSetup`,
    agent: {
      hiddenFromAgents: true,
    },
    noAuth: true,
    handler: async ({ cookies, response }) => handlers.initSetup({ cookies, response }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/twofa/confirmLogin`,
    agent: {
      hiddenFromAgents: true,
    },
    noAuth: true,
    request_schema: confirmLoginBodySchema,
    handler: async ({ body, response, cookies, headers, requestUrl, query }) => {
      return handlers.confirmLogin({ body, response, cookies, headers, requestUrl, query });
    },
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/twofa/confirmLoginWithPasskey`,
    agent: {
      hiddenFromAgents: true,
    },
    noAuth: true,
    request_schema: confirmLoginWithPasskeyBodySchema,
    handler: async ({ body, response, cookies, headers, requestUrl, query }) => {
      return handlers.confirmLoginWithPasskey({ body, response, cookies, headers, requestUrl, query });
    },
  });

  server.endpoint({
    method: "GET",
    path: "/plugin/twofa/skip-allow",
    agent: {
      hiddenFromAgents: true,
    },
    noAuth: true,
    handler: async ({ cookies, response }) => handlers.skipAllow({ cookies, response }),
  });

  server.endpoint({
    method: "GET",
    path: "/plugin/twofa/skip-allow-modal",
    agent: {
      hiddenFromAgents: true,
    },
    handler: async ({ adminUser, headers, cookies, response }) => handlers.skipAllowModal({ adminUser, headers, cookies, response }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/twofa/verify`,
    agent: {
      hiddenFromAgents: true,
    },
    noAuth: false,
    request_schema: verifyTotpBodySchema,
    handler: async ({ adminUser, body, response }) => {
      return handlers.verifyTotp({ adminUser, body, response });
    },
  });
}
