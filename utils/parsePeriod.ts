const PERIOD_RE = /^(\d+)([dhms])$/;

export function parsePeriod(period?: string): number {
  if (!period) return 0;

  const match = PERIOD_RE.exec(period.trim());
  if (!match) throw new Error(`Invalid suggestionPeriod format: ${period}`);

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 'd': return value * 24 * 60 * 60 * 1000;
    case 'h': return value * 60 * 60 * 1000;
    case 'm': return value * 60 * 1000;
    case 's': return value * 1000;
    default: return value;
  }
}
