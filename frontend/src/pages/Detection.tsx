import { useEffect, useState } from 'react';
import { AlertTriangle, Info, ChevronDown, ChevronUp } from 'lucide-react';
import { getAlerts } from '../services/api';
import type { Alert } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import Spinner from '../components/Spinner';

function AlertRow({ alert }: { alert: Alert }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-stone-200 dark:border-stone-800 rounded-lg overflow-hidden
                    bg-white dark:bg-transparent transition-colors">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left transition-colors
                   hover:bg-stone-50 dark:hover:bg-stone-800/50"
        onClick={() => setOpen(o => !o)}
      >
        <AlertTriangle className="w-4 h-4 text-orange-500 shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-stone-800 dark:text-stone-100 font-medium text-sm">
              {alert.event_type}
            </span>
            <SeverityBadge severity={alert.severity} />
            <span className="text-xs text-stone-400 dark:text-stone-500">
              {alert.timestamp?.slice(0, 19)}
            </span>
            {/* method tag — earthy colours, no blue */}
            <span className={`text-xs px-2 py-0.5 rounded ${
              alert.detection_method === 'combined'
                ? 'bg-teal-100    text-teal-700    dark:bg-teal-900/40    dark:text-teal-300'
                : alert.detection_method === 'ml'
                  ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300'
                  : 'bg-stone-100  text-stone-600   dark:bg-stone-800     dark:text-stone-400'
            }`}>
              {alert.detection_method}
            </span>
          </div>
          <div className="text-xs text-stone-400 dark:text-stone-400 mt-0.5 truncate">
            {alert.source_ip} → {alert.affected_asset}
          </div>
        </div>
        {open
          ? <ChevronUp   className="w-4 h-4 text-stone-400 dark:text-stone-500 shrink-0"/>
          : <ChevronDown className="w-4 h-4 text-stone-400 dark:text-stone-500 shrink-0"/>
        }
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-stone-200 dark:border-stone-800
                        bg-stone-50 dark:bg-stone-900/50">
          <div className="grid grid-cols-2 gap-4 mt-3 text-sm">
            <div>
              <div className="text-stone-400 dark:text-stone-500 text-xs mb-1">ML Prediction</div>
              <div className={`font-medium ${
                alert.ml_prediction === 'suspicious'
                  ? 'text-orange-600 dark:text-orange-400'
                  : 'text-emerald-700 dark:text-emerald-400'
              }`}>
                {alert.ml_prediction ?? 'N/A'}
                {alert.confidence_score != null && (
                  <span className="text-stone-400 dark:text-stone-500 text-xs ml-2">
                    ({(alert.confidence_score * 100).toFixed(1)}% confidence)
                  </span>
                )}
              </div>
            </div>
            <div>
              <div className="text-stone-400 dark:text-stone-500 text-xs mb-1">Alert ID</div>
              <div className="text-stone-600 dark:text-stone-300 font-mono text-xs truncate">
                {alert.alert_id}
              </div>
            </div>
          </div>

          <div>
            <div className="text-stone-400 dark:text-stone-500 text-xs mb-1">Detection Reason</div>
            <div className="text-stone-700 dark:text-stone-300 text-sm
                            bg-white dark:bg-stone-800
                            border border-stone-200 dark:border-stone-700 rounded p-2">
              {alert.detection_reason}
            </div>
          </div>

          {alert.evidence.length > 0 && (
            <div>
              <div className="text-stone-400 dark:text-stone-500 text-xs mb-1">Evidence</div>
              <div className="flex flex-wrap gap-2">
                {alert.evidence.map((ev, i) => (
                  <span key={i}
                    className="text-xs bg-stone-100 text-stone-700
                               dark:bg-stone-800 dark:text-stone-300
                               px-2 py-1 rounded font-mono">
                    {String(ev.rule)}: {String(ev.value)}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Recommended action — teal info panel instead of blue */}
          <div>
            <div className="text-stone-400 dark:text-stone-500 text-xs mb-1">Recommended Action</div>
            <div className="panel-info rounded p-2 text-sm leading-relaxed">
              {alert.recommended_action}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Detection() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoad]  = useState(true);
  const [severity, setSev]  = useState('');

  useEffect(() => {
    setLoad(true);
    getAlerts({ page_size: 200, severity: severity || undefined })
      .then(setAlerts).catch(console.error).finally(() => setLoad(false));
  }, [severity]);

  const counts = alerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1; return acc;
  }, {});

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-stone-900 dark:text-stone-100">Threat Detection</h1>
        <p className="text-stone-500 dark:text-stone-400 text-sm">
          {alerts.length} suspicious events detected
        </p>
      </div>

      {/* Severity filter pills — earthy tones */}
      <div className="flex gap-3 flex-wrap">
        {[
          { label:'Critical', key:'critical', cls:'border-red-300    bg-red-50    text-red-700    dark:border-red-800    dark:bg-red-900/50    dark:text-red-300'    },
          { label:'High',     key:'high',     cls:'border-orange-300 bg-orange-50 text-orange-700 dark:border-orange-800 dark:bg-orange-900/50 dark:text-orange-300' },
          { label:'Medium',   key:'medium',   cls:'border-amber-300  bg-amber-50  text-amber-700  dark:border-amber-800  dark:bg-amber-900/50  dark:text-amber-300'  },
          { label:'Low',      key:'low',      cls:'border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300' },
        ].map(({ label, key, cls }) => (
          <button key={key}
            onClick={() => setSev(severity === key ? '' : key)}
            className={`px-3 py-1.5 rounded-lg border text-sm font-medium transition-all ${cls}
                        ${severity === key ? 'ring-2 ring-stone-400/40' : 'opacity-75 hover:opacity-100'}`}>
            {label}: {counts[key] ?? 0}
          </button>
        ))}
        {severity && (
          <button onClick={() => setSev('')}
            className="px-3 py-1.5 text-sm text-stone-500 dark:text-stone-400 hover:text-stone-800 dark:hover:text-stone-100">
            Clear ×
          </button>
        )}
      </div>

      {/* Info banner — teal mist, no blue */}
      <div className="panel-info rounded-lg px-4 py-2 flex items-start gap-2 text-sm">
        <Info className="w-4 h-4 shrink-0 mt-0.5 opacity-70" />
        <span>
          Detections combine ML predictions with rule-based heuristics. Events are labelled&nbsp;
          <strong>suspicious</strong> — not confirmed attacks. All findings require analyst investigation.
        </span>
      </div>

      {loading ? (
        <div className="flex justify-center py-16"><Spinner size={10} /></div>
      ) : alerts.length === 0 ? (
        <div className="card text-center py-16 text-stone-400 dark:text-stone-500">
          No suspicious events detected yet.
        </div>
      ) : (
        <div className="space-y-2">
          {alerts.map(a => <AlertRow key={a.alert_id} alert={a} />)}
        </div>
      )}
    </div>
  );
}
