import axios, { AxiosInstance, AxiosError } from "axios";
import {
  AuditClientConfig,
  AuditRequest,
  AuditResult,
  ApiError,
  AttackCategory,
  MutationStrategy,
} from "./types";

const DEFAULT_CONFIG: Pick<AuditClientConfig, "timeoutMs" | "retries"> = {
  timeoutMs: 120_000,
  retries: 3,
};

export class AuditClient {
  private readonly http: AxiosInstance;
  private readonly config: AuditClientConfig;

  constructor(config: Partial<AuditClientConfig> & { baseUrl: string }) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    this.http = axios.create({
      baseURL: this.config.baseUrl,
      timeout: this.config.timeoutMs,
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "llm-safety-auditor-client/1.0.0",
        ...(this.config.apiKey ? { Authorization: `Bearer ${this.config.apiKey}` } : {}),
      },
    });

    this.http.interceptors.response.use(
      (res) => res,
      (err: AxiosError) => Promise.reject(this.mapError(err))
    );
  }

  /**
   * Submit a new audit job and wait for results.
   * For long-running audits, the server streams partial results via polling.
   */
  async runAudit(request: AuditRequest): Promise<AuditResult> {
    const response = await this.withRetry(() =>
      this.http.post<AuditResult>("/v1/audits", request)
    );
    return response.data;
  }

  /**
   * Fetch the results of a previously submitted audit by ID.
   */
  async getResults(auditId: string): Promise<AuditResult> {
    const response = await this.withRetry(() =>
      this.http.get<AuditResult>(`/v1/audits/${encodeURIComponent(auditId)}`)
    );
    return response.data;
  }

  /**
   * List all past audits, optionally filtered by model endpoint.
   */
  async listAudits(modelEndpoint?: string): Promise<AuditResult[]> {
    const params = modelEndpoint ? { model_endpoint: modelEndpoint } : {};
    const response = await this.http.get<{ audits: AuditResult[] }>("/v1/audits", { params });
    return response.data.audits;
  }

  /**
   * Export a completed audit report as a JSON file payload.
   */
  async exportReport(auditId: string): Promise<string> {
    const result = await this.getResults(auditId);
    return JSON.stringify(result, null, 2);
  }

  /**
   * Retrieve the list of supported attack categories.
   */
  async listCategories(): Promise<AttackCategory[]> {
    const response = await this.http.get<{ categories: AttackCategory[] }>("/v1/attacks/categories");
    return response.data.categories;
  }

  /**
   * Retrieve the list of supported mutation strategies.
   */
  async listStrategies(): Promise<MutationStrategy[]> {
    const response = await this.http.get<{ strategies: MutationStrategy[] }>("/v1/attacks/strategies");
    return response.data.strategies;
  }

  /**
   * Health check — returns true if the API is reachable.
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.http.get("/health", { timeout: 5_000 });
      return true;
    } catch {
      return false;
    }
  }

  private async withRetry<T>(fn: () => Promise<T>): Promise<T> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= this.config.retries; attempt++) {
      try {
        return await fn();
      } catch (err) {
        lastError = err;
        const apiErr = err as ApiError;
        // Don't retry client errors (4xx) except 429 (rate limit)
        if (apiErr.status && apiErr.status >= 400 && apiErr.status < 500 && apiErr.status !== 429) {
          throw err;
        }
        if (attempt < this.config.retries) {
          await this.sleep(Math.min(1000 * 2 ** (attempt - 1), 10_000));
        }
      }
    }
    throw lastError;
  }

  private mapError(err: AxiosError): ApiError {
    const status = err.response?.status ?? 0;
    const data = err.response?.data as Record<string, unknown> | undefined;
    return {
      status,
      code: (data?.["code"] as string) ?? err.code ?? "UNKNOWN",
      message: (data?.["message"] as string) ?? err.message,
      detail: data?.["detail"],
    };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
