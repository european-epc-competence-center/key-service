import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
  Unique,
} from "typeorm";

@Entity("keys")
@Unique("UQ_keys_identifier_type_signature", [
  "identifier",
  "keyType",
  "signatureType",
])
@Index("IDX_keys_type_signature", ["keyType", "signatureType"])
export class EncryptedKey {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column({ type: "text", name: "identifier" })
  @Index("IDX_keys_identifier")
  identifier!: string;

  @Column({ type: "text", name: "keytype" })
  keyType!: string;

  @Column({ type: "text", name: "signaturetype" })
  signatureType!: string;

  @Column({ type: "text", name: "encryptedprivatekey" })
  encryptedPrivateKey!: string;

  @Column({ type: "text", name: "encryptedpublickey" })
  encryptedPublicKey!: string;

  @CreateDateColumn({ name: "createdat" })
  @Index("IDX_keys_created_at")
  createdAt!: Date;
}
