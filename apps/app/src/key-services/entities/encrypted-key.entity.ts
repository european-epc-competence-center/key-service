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

  @Column({ type: "text", name: "key_type" })
  keyType!: string;

  @Column({ type: "text", name: "signature_type" })
  signatureType!: string;

  @Column({ type: "text", name: "encrypted_private_key" })
  encryptedPrivateKey!: string;

  @Column({ type: "text", name: "encrypted_public_key" })
  encryptedPublicKey!: string;

  @CreateDateColumn({ name: "created_at" })
  @Index("IDX_keys_created_at")
  createdAt!: Date;
}
