import type { ReactNode } from 'react';

interface Props {
  label: string;
  value: string | number;
  icon: ReactNode;
  color?: string;
  sub?: string;
}

export default function StatCard({ label, value, icon, color = 'text-emerald-600', sub }: Props) {
  return (
    <div className="card flex items-center gap-4">
      <div className={`p-3 rounded-xl bg-stone-100 dark:bg-stone-800 ${color}`}>
        {icon}
      </div>
      <div>
        <div className="text-2xl font-bold text-stone-900 dark:text-stone-100">{value}</div>
        <div className="text-sm text-stone-500 dark:text-stone-400">{label}</div>
        {sub && <div className="text-xs text-stone-400 dark:text-stone-600 mt-0.5">{sub}</div>}
      </div>
    </div>
  );
}
