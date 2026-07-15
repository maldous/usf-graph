export class GeneratedOutputValidationError extends Error {
  constructor(message, report) {
    super(message);
    this.name = 'GeneratedOutputValidationError';
    this.phase = 'verify-output:independent';
    this.report = report;
    this.findings = report.findings;
  }
}
