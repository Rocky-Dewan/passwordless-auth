import { DataSource } from 'typeorm';
import { config } from '../config';
import { User } from '../models/user.model';
import { AuditLog } from '../models/audit.model';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: config.db.host,
  port: config.db.port,
  username: config.db.user,
  password: config.db.password,
  database: config.db.name,
  synchronize: false,
  logging: config.env === 'development',
  entities: [User, AuditLog],
  migrations: [],
  subscribers: [],
  ssl: config.env === 'production' ? { rejectUnauthorized: false } : false,
});

export async function initDatabase(): Promise<void> {
  await AppDataSource.initialize();
}
