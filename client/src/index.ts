#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import * as fs from "fs";
import * as path from "path";
import { AuditClient } from "./client";
import { formatFullReport, formatRiskLevel } from "./formatters";
import { AuditRequest, AttackCategory, MutationStrategy } from "./types";

const program = new Command();

program
  .name("llm-audit")
  .description("CLI client for the LLM Safety Auditor API")
  .version("1.0.0");

// ---------------------------------------------------------------------------
// audit command
// ---------------------------------------------------------------------------
program
  .command("audit <model-endpoint>")
  .description("Run a safety audit against a model inference endpoint")
  .option("-a, --attacks <number>", "Number of attacks to run", "50")
  .option(
    "-c, --categories <list>",
    "Comma-separated attack categories to include (default: all)",
    ""
  )
  .option(
    "-s, --strategies <list>",
    "Comma-separated mutation strategies to include (default: all)",
    ""
  )
  .option("-o, --output <file>", "Write full JSON report to this file")
  .option("-k, --api-key <key>", "API key for the auditor service", process.env["AUDITOR_API_KEY"])
  .option(
    "--base-url <url>",
    "Base URL of the auditor API",
    process.env["AUDITOR_BASE_URL"] ?? "http://localhost:8000"
  )
  .option("--timeout <ms>", "Request timeout in milliseconds", "120000")
  .option("--workers <n>", "Parallel attack workers", "4")
  .action(async (modelEndpoint: string, opts) => {
    const client = new AuditClient({
      baseUrl: opts.baseUrl as string,
      apiKey: opts.apiKey as string | undefined,
      timeoutMs: parseInt(opts.timeout as string, 10),
      retries: 3,
    });

    console.log(chalk.white.bold("\n  LLM Safety Auditor"));
    console.log(chalk.gray(`  Targeting: ${modelEndpoint}`));
    console.log(chalk.gray(`  API:       ${opts.baseUrl}`));
    console.log("");

    // Health check
    const healthy = await client.healthCheck();
    if (!healthy) {
      console.error(chalk.red(`\n  Error: Cannot reach auditor API at ${opts.baseUrl}`));
      console.error(chalk.gray("  Ensure the Python API server is running: uvicorn api.main:app"));
      process.exit(1);
    }

    const request: AuditRequest = {
      modelEndpoint,
      attackCount: parseInt(opts.attacks as string, 10),
      parallelWorkers: parseInt(opts.workers as string, 10),
    };

    if ((opts.categories as string) !== "") {
      request.categories = (opts.categories as string)
        .split(",")
        .map((c) => c.trim() as AttackCategory);
    }

    if ((opts.strategies as string) !== "") {
      request.strategies = (opts.strategies as string)
        .split(",")
        .map((s) => s.trim() as MutationStrategy);
    }

    console.log(chalk.gray(`  Launching ${request.attackCount} attacks...`));
    console.log("");

    try {
      const result = await client.runAudit(request);
      console.log(formatFullReport(result));

      if (opts.output) {
        const outPath = path.resolve(opts.output as string);
        const json = await client.exportReport(result.auditId);
        fs.writeFileSync(outPath, json, "utf-8");
        console.log(chalk.green(`\n  Report written to: ${outPath}`));
      }

      // Exit 1 if critical failures found
      if (result.summary.criticalFailures > 0) {
        process.exit(1);
      }
    } catch (err) {
      handleError(err);
    }
  });

// ---------------------------------------------------------------------------
// results command — fetch a past audit
// ---------------------------------------------------------------------------
program
  .command("results <audit-id>")
  .description("Fetch and display results for a past audit")
  .option("-o, --output <file>", "Write JSON report to file")
  .option("-k, --api-key <key>", "API key", process.env["AUDITOR_API_KEY"])
  .option("--base-url <url>", "Auditor API base URL", process.env["AUDITOR_BASE_URL"] ?? "http://localhost:8000")
  .action(async (auditId: string, opts) => {
    const client = new AuditClient({
      baseUrl: opts.baseUrl as string,
      apiKey: opts.apiKey as string | undefined,
      timeoutMs: 30_000,
      retries: 2,
    });

    try {
      const result = await client.getResults(auditId);
      console.log(formatFullReport(result));

      if (opts.output) {
        const outPath = path.resolve(opts.output as string);
        const json = await client.exportReport(auditId);
        fs.writeFileSync(outPath, json, "utf-8");
        console.log(chalk.green(`\n  Report written to: ${outPath}`));
      }
    } catch (err) {
      handleError(err);
    }
  });

// ---------------------------------------------------------------------------
// list command — list past audits
// ---------------------------------------------------------------------------
program
  .command("list")
  .description("List past audits")
  .option("-m, --model <endpoint>", "Filter by model endpoint")
  .option("-k, --api-key <key>", "API key", process.env["AUDITOR_API_KEY"])
  .option("--base-url <url>", "Auditor API base URL", process.env["AUDITOR_BASE_URL"] ?? "http://localhost:8000")
  .action(async (opts) => {
    const client = new AuditClient({
      baseUrl: opts.baseUrl as string,
      apiKey: opts.apiKey as string | undefined,
      timeoutMs: 30_000,
      retries: 2,
    });

    try {
      const audits = await client.listAudits(opts.model as string | undefined);

      if (audits.length === 0) {
        console.log(chalk.gray("\n  No audits found.\n"));
        return;
      }

      console.log(chalk.white.bold("\n  Past Audits\n"));
      console.log(
        chalk.gray(
          `  ${"ID".padEnd(36)}  ${"Model Endpoint".padEnd(40)}  ${"Risk".padEnd(12)}  Score`
        )
      );
      console.log(chalk.gray("  " + "─".repeat(100)));

      for (const audit of audits) {
        const riskStr = formatRiskLevel(audit.summary.overallRiskLevel);
        const score = audit.summary.safetyScore.toFixed(1).padStart(5);
        console.log(
          `  ${audit.auditId.padEnd(36)}  ${audit.modelEndpoint.padEnd(40)}  ${riskStr.padEnd(12)}  ${score}`
        );
      }
      console.log("");
    } catch (err) {
      handleError(err);
    }
  });

// ---------------------------------------------------------------------------
// info command — show available categories/strategies
// ---------------------------------------------------------------------------
program
  .command("info")
  .description("List supported attack categories and mutation strategies")
  .option("-k, --api-key <key>", "API key", process.env["AUDITOR_API_KEY"])
  .option("--base-url <url>", "Auditor API base URL", process.env["AUDITOR_BASE_URL"] ?? "http://localhost:8000")
  .action(async (opts) => {
    const client = new AuditClient({
      baseUrl: opts.baseUrl as string,
      apiKey: opts.apiKey as string | undefined,
      timeoutMs: 10_000,
      retries: 1,
    });

    try {
      const [categories, strategies] = await Promise.all([
        client.listCategories(),
        client.listStrategies(),
      ]);

      console.log(chalk.white.bold("\n  Attack Categories:\n"));
      categories.forEach((c) => console.log(chalk.gray(`    • ${c}`)));

      console.log(chalk.white.bold("\n  Mutation Strategies:\n"));
      strategies.forEach((s) => console.log(chalk.gray(`    • ${s}`)));
      console.log("");
    } catch (err) {
      handleError(err);
    }
  });

// ---------------------------------------------------------------------------
// Error handler
// ---------------------------------------------------------------------------
function handleError(err: unknown): never {
  if (err && typeof err === "object" && "status" in err) {
    const apiErr = err as { status: number; code: string; message: string };
    console.error(chalk.red(`\n  API Error [${apiErr.status}] ${apiErr.code}: ${apiErr.message}\n`));
  } else if (err instanceof Error) {
    console.error(chalk.red(`\n  Error: ${err.message}\n`));
  } else {
    console.error(chalk.red(`\n  Unknown error: ${String(err)}\n`));
  }
  process.exit(1);
}

program.parse(process.argv);
