import { DataSource } from "typeorm";
import { cliDbConfig } from "../apps/app/src/config/database.config";

export const AppDataSource = new DataSource(cliDbConfig);
