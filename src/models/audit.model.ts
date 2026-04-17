import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';

export type AuditAction =
  | 'AUTH_REQUEST'
  | 'AUTH_SUCCESS'
  | 'AUTH_FAILURE'
  | 'AUTH_OTP_VERIFIED'
  | 'AUTH_OTP_FAILED'
  | 'AUTH_LINK_USED'
  | 'AUTH_LINK_EXPIRED'
  | 'SESSION_CREATED'
  | 'SESSION_REVOKED'
  | 'SESSION_ROTATED'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_UNLOCKED'
  | 'SUSPICIOUS_LOGIN';

@Entity('audit_logs')
@Index(['userId'])
@Index(['action'])
@Index(['createdAt'])
export class AuditLog {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid', nullable: true })
  userId!: string | null;

  @Column({ type: 'varchar', length: 64 })
  action!: AuditAction;

  @Column({ type: 'varchar', length: 45, nullable: true })
  ip!: string | null;

  @Column({ type: 'text', nullable: true })
  userAgent!: string | null;

  @Column({ type: 'jsonb', nullable: true })
  metadata!: Record<string, unknown> | null;

  @Column({ type: 'boolean', default: true })
  success!: boolean;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt!: Date;
}
