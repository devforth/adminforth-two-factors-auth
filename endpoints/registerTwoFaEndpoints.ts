import type { IHttpServer } from "adminforth";

export function registerTwoFaEndpoints(server: IHttpServer, handlers: any): void {
  server.endpoint({
    method: 'POST',
    path: `/plugin/twofa/initSetup`,
    noAuth: true,
    handler: async ({ cookies }) => handlers.initSetup({ cookies }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/twofa/confirmLogin`,
    noAuth: true,
    handler: async ({ body, response, cookies }) => handlers.confirmLogin({ body, response, cookies }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/twofa/confirmLoginWithPasskey`,
    noAuth: true,
    handler: async ({ body, response, cookies, headers, requestUrl, query }) =>
      handlers.confirmLoginWithPasskey({ body, response, cookies, headers, requestUrl, query }),
  });

  server.endpoint({
    method: "GET",
    path: "/plugin/twofa/skip-allow",
    noAuth: true,
    handler: async ({ cookies }) => handlers.skipAllow({ cookies }),
  });

  server.endpoint({
    method: "GET",
    path: "/plugin/twofa/skip-allow-modal",
    handler: async ({ adminUser, headers, cookies }) => handlers.skipAllowModal({ adminUser, headers, cookies }),
  });

  server.endpoint({
    method: 'POST',
    path: `/plugin/twofa/verify`,
    noAuth: false,
    handler: async ({ adminUser, body }) => handlers.verifyTotp({ adminUser, body }),
  });
}
