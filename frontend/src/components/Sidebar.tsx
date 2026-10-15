import {
  Shield, LayoutDashboard, FileText, AlertTriangle,
  Link2, ShieldCheck, BarChart2,
} from 'lucide-react';

type Page = 'dashboard' | 'logs' | 'detection' | 'incidents' | 'compliance' | 'reports';

interface SidebarProps {
  current:   Page;
  onChange:  (p: Page) => void;
  apiOnline: boolean | null;
}

const navItems: { id: Page; label: string; Icon: React.FC<{ className?: string }> }[] = [
  { id: 'dashboard',  label: 'Dashboard',   Icon: LayoutDashboard },
  { id: 'logs',       label: 'Logs',         Icon: FileText        },
  { id: 'detection',  label: 'Detection',    Icon: AlertTriangle   },
  { id: 'incidents',  label: 'Incidents',    Icon: Link2           },
  { id: 'compliance', label: 'Compliance',   Icon: ShieldCheck     },
  { id: 'reports',    label: 'Reports',      Icon: BarChart2       },
];

export default function Sidebar({ current, onChange, apiOnline }: SidebarProps) {
  return (
    <aside className="w-60 h-screen flex flex-col shrink-0
                      bg-white border-r border-stone-200
                      dark:bg-stone-900 dark:border-stone-800
                      transition-colors duration-200">

      {/* ── Brand ──────────────────────────────────────────── */}
      <div className="flex items-center gap-3 px-5 h-14 border-b
                      border-stone-200 dark:border-stone-800 shrink-0">
        <div className="w-7 h-7 rounded-lg bg-emerald-700 flex items-center justify-center shrink-0">
          <Shield className="w-4 h-4 text-white" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-bold text-stone-800 dark:text-stone-100 tracking-tight">
            CyberSec
          </div>
          <div className="text-[10px] font-medium text-stone-400 dark:text-stone-500 tracking-widest uppercase">
            Analytics
          </div>
        </div>
      </div>

      {/* ── Section label + Nav ────────────────────────────── */}
      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-0.5">
        <p className="px-2 mb-2 text-[10px] font-semibold tracking-widest uppercase
                      text-stone-400 dark:text-stone-600">
          Navigation
        </p>

        {navItems.map(({ id, label, Icon }) => (
          <button
            key={id}
            onClick={() => onChange(id)}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg
                        text-sm font-medium transition-all duration-150
              ${current === id
                ? 'bg-emerald-700 text-white shadow-sm'
                : 'text-stone-500 hover:bg-stone-100 hover:text-stone-900 dark:text-stone-400 dark:hover:bg-stone-800 dark:hover:text-stone-100'
              }`}
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </button>
        ))}
      </div>

      {/* ── Footer status ──────────────────────────────────── */}
      <div className="px-4 py-4 border-t border-stone-200 dark:border-stone-800 shrink-0">
        <div className="flex items-center justify-between">
          {/* API status dot + text */}
          <div className="flex items-center gap-2">
            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
              apiOnline === null
                ? 'bg-stone-300 dark:bg-stone-600'
                : apiOnline
                  ? 'bg-emerald-500'
                  : 'bg-red-500'
            }`} />
            <span className="text-xs text-stone-400 dark:text-stone-500">
              {apiOnline === null ? 'Connecting…' : apiOnline ? 'API Online' : 'API Offline'}
            </span>
          </div>
          <span className="text-[10px] text-stone-300 dark:text-stone-700 font-medium">
            v1.0
          </span>
        </div>
      </div>

    </aside>
  );
}
