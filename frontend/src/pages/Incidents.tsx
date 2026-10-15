import { useEffect, useState } from 'react';
import { Link2, ChevronDown, ChevronUp, Clock, Server } from 'lucide-react';
import { getIncidents } from '../services/api';
import type { Incident } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import Spinner from '../components/Spinner';

function IncidentCard({ inc }: { inc: Incident }) {
  const [open, setOpen] = useState(false);
  return (
    <div
      className="card cursor-pointer transition-shadow hover:shadow-md dark:hover:shadow-none
                 hover:border-slate-300 dark:hover:border-gray-700"
      onClick={() => setOpen(o => !o)}
    >
      <div className="flex items-start gap-3">
        <Link2 className="w-5 h-5 text-purple-500 shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-slate-800 dark:text-white font-semibold text-sm">
              {inc.category}
            </span>
            <SeverityBadge severity={inc.severity} />
            <span className="text-xs bg-slate-100 dark:bg-gray-800 text-slate-500 dark:text-gray-400
                             px-2 py-0.5 rounded">
              {inc.alert_count} alert{inc.alert_count !== 1 ? 's' : ''}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded ${
              inc.status === 'open'
                ? 'text-yellow-600 bg-yellow-100 dark:text-yellow-300 dark:bg-yellow-900/30'
                : 'text-green-600 bg-green-100 dark:text-green-300 dark:bg-green-900/30'
            }`}>
              {inc.status}
            </span>
          </div>

          <div className="flex gap-4 mt-1 text-xs text-slate-400 dark:text-gray-400">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {inc.first_seen?.slice(0, 16)} – {inc.last_seen?.slice(0, 16)}
            </span>
          </div>

          {inc.affected_assets.length > 0 && (
            <div className="flex gap-1.5 mt-1.5 flex-wrap">
              {inc.affected_assets.map(a => (
                <span key={a}
                  className="flex items-center gap-1 text-xs
                             text-slate-500 dark:text-gray-400
                             bg-slate-100 dark:bg-gray-800 px-2 py-0.5 rounded">
                  <Server className="w-3 h-3" />{a}
                </span>
              ))}
            </div>
          )}
        </div>
        {open
          ? <ChevronUp className="w-4 h-4 text-slate-400 dark:text-gray-500"/>
          : <ChevronDown className="w-4 h-4 text-slate-400 dark:text-gray-500"/>
        }
      </div>

      {open && (
        <div
          className="mt-4 pt-4 border-t border-slate-200 dark:border-gray-800 space-y-3 text-sm"
          onClick={e => e.stopPropagation()}
        >
          <div>
            <div className="text-slate-400 dark:text-gray-500 text-xs mb-1">Incident ID</div>
            <div className="font-mono text-slate-600 dark:text-gray-300 text-xs">{inc.incident_id}</div>
          </div>
          <div>
            <div className="text-slate-400 dark:text-gray-500 text-xs mb-1">Evidence Summary</div>
            <div className="text-slate-700 dark:text-gray-300
                            bg-slate-100 dark:bg-gray-800 rounded p-2 text-xs">
              {inc.evidence_summary}
            </div>
          </div>
          <div>
            <div className="text-slate-400 dark:text-gray-500 text-xs mb-1">
              Related Alert IDs ({inc.alert_ids.length})
            </div>
            <div className="flex flex-wrap gap-1 max-h-20 overflow-y-auto">
              {inc.alert_ids.map(id => (
                <span key={id}
                  className="font-mono text-xs text-slate-400 dark:text-gray-500
                             bg-slate-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">
                  {id.slice(0,16)}…
                </span>
              ))}
            </div>
          </div>
          <div>
            <div className="text-slate-400 dark:text-gray-500 text-xs mb-1">
              Recommended Remediation
            </div>
            <div className="text-blue-700 dark:text-blue-300
                            bg-blue-50 dark:bg-blue-900/20
                            border border-blue-200 dark:border-blue-900/40 rounded p-2 text-xs">
              {inc.remediation}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Incidents() {
  const [incidents, setInc] = useState<Incident[]>([]);
  const [loading, setLoad]  = useState(true);

  useEffect(() => {
    getIncidents({ page_size: 200 })
      .then(setInc).catch(console.error).finally(() => setLoad(false));
  }, []);

  const bySev = incidents.reduce<Record<string, number>>((acc, i) => {
    acc[i.severity] = (acc[i.severity] ?? 0) + 1; return acc;
  }, {});

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
          Incident Correlation
        </h1>
        <p className="text-slate-500 dark:text-gray-400 text-sm">
          {incidents.length} potential incidents identified
        </p>
      </div>

      {/* Severity summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          ['critical','text-red-500'],
          ['high','text-orange-500'],
          ['medium','text-yellow-500'],
          ['low','text-green-500'],
        ].map(([s, c]) => (
          <div key={s} className="card text-center">
            <div className={`text-2xl font-bold ${c}`}>{bySev[s] ?? 0}</div>
            <div className="text-xs text-slate-400 dark:text-gray-500 mt-1 capitalize">{s}</div>
          </div>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-16"><Spinner size={10} /></div>
      ) : incidents.length === 0 ? (
        <div className="card text-center py-16 text-slate-400 dark:text-gray-500">
          No incidents correlated yet.
        </div>
      ) : (
        <div className="space-y-3">
          {incidents.map(inc => <IncidentCard key={inc.incident_id} inc={inc} />)}
        </div>
      )}
    </div>
  );
}
