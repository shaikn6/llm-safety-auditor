import chalk from "chalk";
import { AuditResult, AttackResult, RiskLevel, AuditSummary } from "./types";

const RISK_COLORS: Record<RiskLevel, chalk.Chalk> = {
  critical: chalk.bgRed.white.bold,
  high:     chalk.red.bold,
  medium:   chalk.yellow.bold,
  low:      chalk.cyan,
  none:     chalk.green,
};

const RISK_ICONS: Record<RiskLevel, string> = {
  critical: "✖✖",
  high:     "✖ ",
  medium:   "⚠ ",
  low:      "◆ ",
  none:     "✔ ",
};

export function formatRiskLevel(level: RiskLevel): string {
  const color = RISK_COLORS[level];
  const icon = RISK_ICONS[level];
  return color(`${icon}${level.toUpperCase()}`);
}

export function formatSummaryBanner(summary: AuditSummary): string {
  const lines: string[] = [];
  const scoreColor = summary.safetyScore >= 80
    ? chalk.green.bold
    : summary.safetyScore >= 60
    ? chalk.yellow.bold
    : chalk.red.bold;

  lines.push(chalk.gray("─".repeat(60)));
  lines.push(chalk.white.bold("  LLM Safety Audit Report"));
  lines.push(chalk.gray("─".repeat(60)));
  lines.push(
    `  Safety Score: ${scoreColor(summary.safetyScore.toFixed(1) + "/100")}   ` +
    `Risk Level: ${formatRiskLevel(summary.overallRiskLevel)}`
  );
  lines.push(chalk.gray("─".repeat(60)));
  lines.push(
    chalk.white(`  Attacks run:  `) + chalk.cyan.bold(summary.totalAttacks.toString().padStart(5))
  );
  lines.push(
    chalk.white(`  Resisted:     `) + chalk.green.bold(summary.passed.toString().padStart(5))
  );
  lines.push(
    chalk.white(`  Failed:       `) + chalk.red.bold(summary.failed.toString().padStart(5))
  );
  lines.push("");
  lines.push(
    `  ${chalk.red.bold("Critical")} ${summary.criticalFailures.toString().padStart(4)}  ` +
    `${chalk.red("High")} ${summary.highFailures.toString().padStart(4)}  ` +
    `${chalk.yellow("Medium")} ${summary.mediumFailures.toString().padStart(4)}  ` +
    `${chalk.cyan("Low")} ${summary.lowFailures.toString().padStart(4)}`
  );
  lines.push(chalk.gray("─".repeat(60)));
  lines.push(
    chalk.white(`  Duration: `) + chalk.gray(`${(summary.durationMs / 1000).toFixed(1)}s`)
  );
  lines.push(chalk.gray("─".repeat(60)));

  return lines.join("\n");
}

export function formatAttackResult(result: AttackResult, index: number): string {
  const statusIcon = result.passed ? chalk.green("✔") : chalk.red("✖");
  const riskStr = formatRiskLevel(result.riskLevel);
  const scoreStr = chalk.gray(`${(result.detectionScore * 100).toFixed(0)}% detected`);
  const latStr = chalk.gray(`${result.latencyMs}ms`);

  const lines: string[] = [];
  lines.push(
    `  ${String(index + 1).padStart(3)}. ${statusIcon} [${result.attack.category}] ` +
    `${chalk.white(result.attack.strategy)}  ${riskStr}  ${scoreStr}  ${latStr}`
  );

  if (!result.passed) {
    lines.push(
      chalk.gray(`       Reasoning: `) +
      chalk.italic(truncate(result.reasoning, 100))
    );
  }

  return lines.join("\n");
}

export function formatFailureDetail(result: AttackResult): string {
  const lines: string[] = [];
  lines.push(chalk.gray("  ─".repeat(30)));
  lines.push(
    chalk.red.bold(`  FAILURE: `) + chalk.white(result.attack.description)
  );
  lines.push(chalk.gray(`  Category:  `) + chalk.white(result.attack.category));
  lines.push(chalk.gray(`  Strategy:  `) + chalk.white(result.attack.strategy));
  lines.push(chalk.gray(`  Risk:      `) + formatRiskLevel(result.riskLevel));
  lines.push(chalk.gray(`  Score:     `) + `${(result.detectionScore * 100).toFixed(1)}%`);
  lines.push(chalk.gray(`  Reasoning: `) + chalk.italic(result.reasoning));
  lines.push("");
  lines.push(chalk.gray.bold(`  Prompt snippet:`));
  lines.push(chalk.gray(`    ${truncate(result.attack.prompt, 200)}`));
  if (result.modelResponse) {
    lines.push("");
    lines.push(chalk.gray.bold(`  Model response snippet:`));
    lines.push(chalk.gray(`    ${truncate(result.modelResponse, 200)}`));
  }
  return lines.join("\n");
}

export function formatFullReport(audit: AuditResult): string {
  const lines: string[] = [];

  lines.push("");
  lines.push(chalk.white.bold(`  Audit ID:    `) + chalk.gray(audit.auditId));
  lines.push(chalk.white.bold(`  Model:       `) + chalk.cyan(audit.modelEndpoint));
  lines.push(
    chalk.white.bold(`  Period:      `) +
    chalk.gray(
      `${new Date(audit.startedAt).toLocaleString()} → ${new Date(audit.completedAt).toLocaleString()}`
    )
  );
  lines.push("");
  lines.push(formatSummaryBanner(audit.summary));
  lines.push("");

  if (audit.results.length > 0) {
    lines.push(chalk.white.bold("  Attack Results:"));
    lines.push("");
    audit.results.forEach((r, i) => {
      lines.push(formatAttackResult(r, i));
    });
  }

  const failures = audit.results.filter((r) => !r.passed);
  if (failures.length > 0) {
    lines.push("");
    lines.push(chalk.red.bold(`  Top Failures (${failures.length}):`));
    failures
      .sort((a, b) => riskWeight(b.riskLevel) - riskWeight(a.riskLevel))
      .slice(0, 5)
      .forEach((r) => {
        lines.push(formatFailureDetail(r));
      });
  }

  return lines.join("\n");
}

function riskWeight(level: RiskLevel): number {
  const weights: Record<RiskLevel, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    none: 0,
  };
  return weights[level];
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + "...";
}
