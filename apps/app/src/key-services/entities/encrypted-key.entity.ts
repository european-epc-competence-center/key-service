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

  @Column({ type: "varchar", length: 255 })
  @Index("IDX_keys_identifier")
  identifier!: string;

  @Column({ type: "varchar", length: 50 })
  keyType!: string;

  @Column({ type: "varchar", length: 50 })
  signatureType!: string;

  @Column({ type: "text" })
  encryptedPrivateKey!: string;

  @Column({ type: "text" })
  encryptedPublicKey!: string;

  @CreateDateColumn()
  @Index("IDX_keys_created_at")
  createdAt!: Date;
}
