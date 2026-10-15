import { useEffect, useState, useCallback } from 'react';
import { ShieldCheck, AlertCircle, ChevronDown, ChevronUp, ChevronLeft, ChevronRight } from 'lucide-react';
import { getCompliance, getComplianceSummary } from '../services/api';
import type { ComplianceMapping } from '../types';
import Spinner from '../components/Spinner';

const RISK_BORDER: Record<string, string> = {
  critical: 'border-red-300    bg-red-50/50    dark:border-red-800    dark:bg-red-900/10',
  high:     'border-orange-300 bg-orange-50/50 dark:border-orange-800 dark:bg-orange-900/10',
  medium:   'border-yellow-300 bg-yellow-50/50 dark:border-yellow-800 dark:bg-yellow-900/10',
  low:      'border-green-300  bg-green-50/50  dark:border-green-800  dark:bg-green-900/10',
};
const RISK_BADGE: Record<string, string> = {
  critical: 'text-red-600    bg-red-100    dark:text-red-300    dark:bg-red-900/40',
  high:     'text-orange-600 bg-orange-100 dark:text-orange-300 dark:bg-orange-900/40',
  medium:   'text-yellow-600 bg-yellow-100 dark:text-yellow-300 dark:bg-yellow-900/40',
  low:      'text-green-600  bg-green-100  dark:text-green-300  dark:bg-green-900/40',
};

function MappingCard({ m }: { m: ComplianceMapping }) {
  const [open, setOpen] = useState(false);
  const borderCls = RISK_BORDER[m.risk_level] ?? 'border-slate-200 dark:border-gray-700';
  const badgeCls  = RISK_BADGE[m.risk_level]  ?? 'text-slate-600 bg-slate-100 dark:text-gray-300 dark:bg-gray-800';

  return (
    <div className={`border rounded-lg overflow-hidden transition-colors ${borderCls}`}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left
                   hover:bg-black/5 dark:hover:bg-white/5 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <ShieldCheck className="w-4 h-4 text-blue-500 shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-blue-600 dark:text-blue-300
                             bg-blue-100 dark:bg-blue-900/30 px-2 py-0.5 rounded">
              {m.control_id}
            </span>
            <span className="text-slate-800 dark:text-white text-sm font-medium truncate">
              {m.control_title}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded font-medium ${badgeCls}`}>
              {m.risk_level}
            </span>
          </div>
          <div className="text-xs text-slate-400 dark:text-gray-500 mt-0.5">
            {m.framework} v{m.framework_version}
          </div>
        </div>
        {open
          ? <ChevronUp   className="w-4 h-4 text-slate-400 dark:text-gray-500 shrink-0" />
          : <ChevronDown className="w-4 h-4 text-slate-400 dark:text-gray-500 shrink-0" />
        }
      </button>

      {open && (
        <div className="px-4 pb-4 pt-1 space-y-2 text-sm border-t border-slate-100 dark:border-gray-800">
          <div className="pt-2">
            <div className="text-slate-400 dark:text-gray-500 text-xs mb-1 font-medium uppercase tracking-wide">Finding</div>
            <div className="text-slate-700 dark:text-gray-300">{m.finding_description}</div>
          </div>
          <div>
            <div className="text-slate-400 dark:text-gray-500 text-xs mb-1 font-medium uppercase tracking-wide">Evidence</div>
            <div className="text-slate-600 dark:text-gray-400
                            bg-slate-100 dark:bg-gray-800 rounded p-2 text-xs font-mono leading-relaxed">
              {m.evidence}
            </div>
          </div>
          <div>
            <div className="text-slate-400 dark:text-gray-500 text-xs mb-1 font-medium uppercase tracking-wide">Remediation</div>
            <div className="text-blue-700 dark:text-blue-300
                            bg-blue-50 dark:bg-blue-900/20
                            border border-blue-200 dark:border-blue-900/30 rounded p-2 text-xs leading-relaxed">
              {m.remediation}
            </div>
          </div>
          <div className="flex items-start gap-1.5
                          bg-yellow-50 dark:bg-yellow-900/20
                          border border-yellow-200 dark:border-yellow-800/30 rounded p-2">
            <AlertCircle className="w-3.5 h-3.5 text-yellow-500 dark:text-yellow-400 shrink-0 mt-0.5" />
            <p className="text-yellow-700 dark:text-yellow-300 text-xs leading-relaxed">{m.disclaimer}</p>
          </div>
        </div>
      )}
    </div>
  );
}

const PAGE_SIZE = 20;
const FRAMEWORKS = ['ISO', 'NIST'];

export default function Compliance() {
  const [items, setItems]         = useState<ComplianceMapping[]>([]);
  const [total, setTotal]         = useState(0);
  const [page, setPage]           = useState(1);
  const [loading, setLoad]        = useState(true);
  const [framework, setFW]        = useState('');
  const [riskFilter, setRisk]     = useState('');
  const [riskCounts, setRiskCnt]  = useState<Record<string, number>>({});

  const fetch = useCallback(() => {
    setLoad(true);
    getCompliance({
      page,
      page_size: PAGE_SIZE,
      framework: framework || undefined,
      risk_level: riskFilter || undefined,
    })
      .then(d => { setItems(d.items); setTotal(d.total); })
      .catch(console.error)
      .finally(() => setLoad(false));
  }, [page, framework, riskFilter]);

  useEffect(() => { fetch(); }, [fetch]);

  // Load summary counts separately (fast, tiny payload)
  useEffect(() => {
    getComplianceSummary()
      .then(setRiskCnt)
      .catch(() => setRiskCnt({}));
  }, []);

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
          Compliance Mappings
        </h1>
        <p className="text-slate-500 dark:text-gray-400 text-sm">
          {total} unique control associations
        </p>
      </div>

      {/* Disclaimer */}
      <div className="bg-yellow-50 dark:bg-yellow-900/20
                      border border-yellow-200 dark:border-yellow-800/40
                      rounded-lg px-4 py-2.5 flex items-start gap-2 text-sm
                      text-yellow-700 dark:text-yellow-300">
        <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-yellow-500" />
        <span>
          These are <strong>suggested associations</strong> only — not formal audit findings,
          compliance certifications, or proof of control violations. A qualified security auditor
          must assess applicability.
        </span>
      </div>

      {/* Risk summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          ['critical', 'text-red-500'],
          ['high',     'text-orange-500'],
          ['medium',   'text-yellow-500'],
          ['low',      'text-green-500'],
        ].map(([r, c]) => (
          <button
            key={r}
            onClick={() => { setRisk(riskFilter === r ? '' : r); setPage(1); }}
            className={`card text-center transition-all hover:shadow-md
                        ${riskFilter === r ? 'ring-2 ring-blue-400' : ''}`}
          >
            <div className={`text-xl font-bold ${c}`}>{riskCounts[r] ?? 0}</div>
            <div className="text-xs text-slate-400 dark:text-gray-500 mt-1 capitalize">{r}</div>
          </button>
        ))}
      </div>

      {/* Filters row */}
      <div className="flex gap-2 flex-wrap items-center">
        <span className="text-xs text-slate-400 dark:text-gray-500 font-medium">Framework:</span>
        {['', ...FRAMEWORKS].map(f => (
          <button
            key={f || 'all'}
            onClick={() => { setFW(f); setPage(1); }}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors
              ${framework === f
                ? 'bg-blue-600 text-white'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-gray-800 dark:text-gray-400 dark:hover:text-white'
              }`}
          >
            {f || 'All'}
          </button>
        ))}
        {(framework || riskFilter) && (
          <button
            onClick={() => { setFW(''); setRisk(''); setPage(1); }}
            className="text-xs text-slate-400 hover:text-slate-700 dark:hover:text-white ml-2"
          >
            Clear filters ×
          </button>
        )}
      </div>

      {/* Mapping cards */}
      {loading ? (
        <div className="flex justify-center py-16"><Spinner size={10} /></div>
      ) : items.length === 0 ? (
        <div className="card text-center py-16 text-slate-400 dark:text-gray-500">
          No compliance mappings found.
        </div>
      ) : (
        <div className="space-y-2">
          {items.map(m => (
            <MappingCard key={`${m.framework}-${m.control_id}-${m.mapping_id}`} m={m} />
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-2">
          <span className="text-sm text-slate-500 dark:text-gray-400">
            Page {page} of {totalPages} · {total} total controls
          </span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage(p => p - 1)}
              className="p-1.5 rounded bg-slate-100 text-slate-500 hover:bg-slate-200
                         dark:bg-gray-800 dark:text-gray-400 dark:hover:bg-gray-700 disabled:opacity-40"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage(p => p + 1)}
              className="p-1.5 rounded bg-slate-100 text-slate-500 hover:bg-slate-200
                         dark:bg-gray-800 dark:text-gray-400 dark:hover:bg-gray-700 disabled:opacity-40"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
