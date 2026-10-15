import { useEffect, useState } from 'react';
import { BarChart2, Download, Plus, CheckCircle, AlertCircle, Clock } from 'lucide-react';
import { getReports, generateReport, downloadReport } from '../services/api';
import type { Report } from '../types';
import Spinner from '../components/Spinner';

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoad]    = useState(true);
  const [generating, setGen]  = useState(false);
  const [genMsg, setMsg]      = useState<{ ok: boolean; msg: string } | null>(null);
  const [title, setTitle]     = useState('Security Assessment Report');

  const fetchReports = () => {
    setLoad(true);
    getReports().then(setReports).catch(console.error).finally(() => setLoad(false));
  };

  useEffect(() => { fetchReports(); }, []);

  const handleGenerate = async () => {
    setGen(true); setMsg(null);
    try {
      const r = await generateReport(title);
      setMsg({ ok: true, msg: `Report "${r.title}" generated (ID: ${r.report_id.slice(0,12)}…)` });
      fetchReports();
    } catch (e: unknown) {
      setMsg({ ok: false, msg: e instanceof Error ? e.message : 'Generation failed' });
    } finally {
      setGen(false);
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Security Reports</h1>
        <p className="text-slate-500 dark:text-gray-400 text-sm">
          Generate and download PDF security assessment reports
        </p>
      </div>

      {/* Generate panel */}
      <div className="card space-y-4">
        <h2 className="font-semibold text-slate-800 dark:text-white flex items-center gap-2">
          <Plus className="w-4 h-4 text-blue-500" /> Generate New Report
        </h2>
        <div className="flex gap-3 flex-wrap">
          <input
            className="field flex-1 min-w-[200px]"
            placeholder="Report title…"
            value={title}
            onChange={e => setTitle(e.target.value)}
          />
          <button
            onClick={handleGenerate}
            disabled={generating}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700
                       disabled:opacity-50 text-white px-5 py-2 rounded-lg
                       text-sm font-medium transition-colors"
          >
            {generating ? <Spinner size={4} /> : <BarChart2 className="w-4 h-4" />}
            {generating ? 'Generating…' : 'Generate PDF'}
          </button>
        </div>
        <p className="text-xs text-slate-400 dark:text-gray-500">
          Report is generated from current database: alerts, incidents, compliance mappings, and model metrics.
        </p>

        {genMsg && (
          <div className={`flex items-center gap-2 p-3 rounded-lg text-sm
            ${genMsg.ok
              ? 'bg-green-50 text-green-700 border border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-800'
              : 'bg-red-50  text-red-700  border border-red-200  dark:bg-red-900/30  dark:text-red-300  dark:border-red-800'
            }`}>
            {genMsg.ok
              ? <CheckCircle className="w-4 h-4 shrink-0"/>
              : <AlertCircle className="w-4 h-4 shrink-0"/>
            }
            {genMsg.msg}
          </div>
        )}
      </div>

      {/* Report list */}
      {loading ? (
        <div className="flex justify-center py-10"><Spinner size={8} /></div>
      ) : reports.length === 0 ? (
        <div className="card text-center py-16 text-slate-400 dark:text-gray-500">
          No reports generated yet. Click "Generate PDF" above.
        </div>
      ) : (
        <div className="space-y-3">
          {reports.map(r => (
            <div key={r.report_id} className="card flex items-center gap-4">
              <BarChart2 className="w-8 h-8 text-blue-500 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="text-slate-800 dark:text-white font-medium">{r.title}</div>
                <div className="flex items-center gap-3 mt-1 text-xs text-slate-400 dark:text-gray-400">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />{r.generated_at?.slice(0,19)}
                  </span>
                  <span className="font-mono">{r.report_id.slice(0,12)}…</span>
                  <span className={`px-2 py-0.5 rounded ${
                    r.status === 'completed'
                      ? 'text-green-600 bg-green-100 dark:text-green-300 dark:bg-green-900/30'
                      : 'text-yellow-600 bg-yellow-100 dark:text-yellow-300 dark:bg-yellow-900/30'
                  }`}>
                    {r.status}
                  </span>
                </div>
                {r.summary && (
                  <div className="flex gap-4 mt-1 text-xs text-slate-400 dark:text-gray-500">
                    <span>Logs: {(r.summary.total_logs as number) ?? 0}</span>
                    <span>Alerts: {(r.summary.total_alerts as number) ?? 0}</span>
                    <span>Incidents: {(r.summary.total_incidents as number) ?? 0}</span>
                  </div>
                )}
              </div>
              <button
                onClick={() => downloadReport(r.report_id)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors
                           bg-slate-100 hover:bg-slate-200 text-slate-600 hover:text-slate-800
                           dark:bg-gray-800 dark:hover:bg-gray-700 dark:text-gray-300 dark:hover:text-white"
              >
                <Download className="w-4 h-4" /> Download
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
