import type { AdminForthResource, AdminUser, IAdminForth } from "adminforth";
import type { PluginOptions } from "../types.js";
import type { AnyRecord } from "../utils/types.js";

export class UserRepository {
  constructor(
    private readonly adminforth: IAdminForth,
    private readonly options: PluginOptions,
  ) {}

  public getAuthResource(): AdminForthResource {
    return this.adminforth.config.resources.find(r => r.resourceId === this.adminforth.config.auth.usersResourceId);
  }

  public getUserPkField(): string {
    return this.getAuthResource().columns.find(c => c.primaryKey).name;
  }

  public getUserPk(adminUser: AdminUser): string {
    return adminUser.dbUser[this.getUserPkField()];
  }

  public async getAuthUser(pk: string): Promise<AnyRecord> {
    const authResource = this.getAuthResource();
    const connector = this.adminforth.connectors[authResource.dataSource];
    return connector.getRecordByPrimaryKey(authResource, pk);
  }

  public getSecret(user: AnyRecord): string {
    return user[this.options.twoFaSecretFieldName];
  }

  public async updateSecret(pk: string, secret: string): Promise<void> {
    const authResource = this.getAuthResource();
    const connector = this.adminforth.connectors[authResource.dataSource];
    await connector.updateRecord({
      resource: authResource,
      recordId: pk,
      newValues: { [this.options.twoFaSecretFieldName]: secret },
    });
  }
}
