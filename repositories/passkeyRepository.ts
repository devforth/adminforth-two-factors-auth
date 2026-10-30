import { Filters } from "adminforth";
import type { AdminForthResource, AdminUser, IAdminForth } from "adminforth";
import type { PluginOptions } from "../types.js";
import type { AnyRecord } from "../utils/types.js";

export class PasskeyRepository {
  constructor(
    private readonly adminforth: IAdminForth,
    private readonly options: PluginOptions,
  ) {}

  public getCredentialResource(): AdminForthResource {
    return this.adminforth.config.resources.find(r => r.resourceId === this.options.passkeys.credentialResourceID);
  }

  public getCredentialResourcePkField(): string {
    return this.getCredentialResource().columns.find(c => c.primaryKey).name;
  }

  public async getByCredentialId(credentialId: string): Promise<AnyRecord> {
    return this.adminforth.resource(this.options.passkeys.credentialResourceID).get([
      Filters.EQ(this.options.passkeys.credentialIdFieldName, credentialId),
    ]);
  }

  public async getByCredentialIdAndUserId(credentialId: string, userId: string): Promise<AnyRecord> {
    return this.adminforth.resource(this.options.passkeys.credentialResourceID).get([
      Filters.EQ(this.options.passkeys.credentialIdFieldName, credentialId),
      Filters.EQ(this.options.passkeys.credentialUserIdFieldName, userId),
    ]);
  }

  public async listByUserId(userId: string): Promise<AnyRecord[]> {
    return this.adminforth.resource(this.options.passkeys.credentialResourceID).list([
      Filters.EQ(this.options.passkeys.credentialUserIdFieldName, userId),
    ]);
  }

  public async hasByUserId(userId: string): Promise<boolean> {
    const passkeys = await this.listByUserId(userId);
    return passkeys && passkeys.length > 0;
  }

  public async create(record: AnyRecord, adminUser: AdminUser): Promise<void> {
    const { error } = await this.ownerWriter(adminUser).create(record);
    if (error) {
      throw new Error(error);
    }
  }

  public async updateMeta(passkeyRecord: AnyRecord, meta: AnyRecord): Promise<void> {
    await this.adminforth
      .resource(this.options.passkeys.credentialResourceID)
      .update(passkeyRecord[this.getCredentialResourcePkField()], {
        [this.options.passkeys.credentialMetaFieldName]: meta,
      });
  }

  public async update(passkeyRecord: AnyRecord, newRecord: AnyRecord, adminUser: AdminUser): Promise<void> {
    const { error } = await this.ownerWriter(adminUser, { oldRecord: passkeyRecord })
      .update(passkeyRecord[this.getCredentialResourcePkField()], newRecord);
    if (error) {
      throw new Error(error);
    }
  }

  public async delete(passkeyRecord: AnyRecord, adminUser: AdminUser): Promise<void> {
    await this.ownerWriter(adminUser, { record: passkeyRecord })
      .delete(passkeyRecord[this.getCredentialResourcePkField()]);
  }

  /**
   * Users manage their own passkeys and the plugin checks the ownership itself, so these are system
   * writes on the user's behalf, which run the resource hooks (e.g. the audit log).
   */
  private ownerWriter(adminUser: AdminUser, snapshot: { record?: AnyRecord; oldRecord?: AnyRecord } = {}) {
    return this.adminforth.resource(this.options.passkeys.credentialResourceID).asSystem({ adminUser, ...snapshot });
  }
}
