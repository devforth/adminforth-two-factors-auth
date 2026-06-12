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
    await this.adminforth.createResourceRecord({
      resource: this.getCredentialResource(),
      record,
      adminUser,
    });
  }

  public async updateMeta(passkeyRecord: AnyRecord, meta: AnyRecord): Promise<void> {
    await this.adminforth
      .resource(this.options.passkeys.credentialResourceID)
      .update(passkeyRecord[this.getCredentialResourcePkField()], {
        [this.options.passkeys.credentialMetaFieldName]: meta,
      });
  }

  public async update(passkeyRecord: AnyRecord, newRecord: AnyRecord, adminUser: AdminUser): Promise<void> {
    await this.adminforth.updateResourceRecord({
      resource: this.getCredentialResource(),
      recordId: passkeyRecord[this.getCredentialResourcePkField()],
      oldRecord: passkeyRecord,
      record: newRecord,
      adminUser,
    });
  }

  public async delete(passkeyRecord: AnyRecord, adminUser: AdminUser): Promise<void> {
    await this.adminforth.deleteResourceRecord({
      resource: this.getCredentialResource(),
      recordId: passkeyRecord[this.getCredentialResourcePkField()],
      record: passkeyRecord,
      adminUser,
    });
  }
}
