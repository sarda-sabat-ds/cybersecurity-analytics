interface Props { severity: string }

export default function SeverityBadge({ severity }: Props) {
  const map: Record<string, string> = {
    critical: 'badge-critical',
    high:     'badge-high',
    medium:   'badge-medium',
    low:      'badge-low',
  };
  const cls = map[severity?.toLowerCase()] ?? 'badge-low';
  return <span className={cls}>{severity?.toUpperCase()}</span>;
}
