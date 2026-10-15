import { useEffect, useState, useRef } from 'react';
import { Search, Upload, ChevronLeft, ChevronRight, AlertCircle, CheckCircle } from 'lucide-react';
import { getLogs, uploadLogs } from '../services/api';
import type { PaginatedLogs } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import Spinner from '../components/Spinner';

export default function Logs() {
  const [data, setData]         = useState<PaginatedLogs | null>(null);
  const [loading, setLoad]      = useState(true);
  const [page, setPage]         = useState(1);
  const [severity, setSeverity] = useState('');
  const [eventType, setEType]   = useState('');
  const [sourceIp, setSrcIp]    = useState('');
  const [uploadMsg, setMsg]     = useState<{ ok: boolean; msg: string } | null>(null);
  const [uploading, setUpl]     = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const PAGE_SIZE = 50;

  const fetchLogs = () => {
    setLoad(true);
    getLogs({ page, page_size: PAGE_SIZE,
      severity: severity || undefined,
      event_type: eventType || undefined,
      source_ip: sourceIp || undefined })
      .then(setData).catch(console.error).finally(() => setLoad(false));
  };

  useEffect(() => { fetchLogs(); }, [page, severity]);

  const handleSearch = (e: React.FormEvent) => { e.preventDefault(); setPage(1); fetchLogs(); };

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUpl(true); setMsg(null);
    try {
      const res = await uploadLogs(file);
      setMsg({ ok: true, msg: res.message });
      fetchLogs();
    } catch (err: unknown) {
      setMsg({ ok: false, msg: err instanceof Error ? err.message : 'Upload failed' });
    } finally {
      setUpl(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-stone-900 dark:text-stone-100">Security Logs</h1>
          <p className="text-stone-500 dark:text-stone-400 text-sm">
            Total: {data?.total.toLocaleString() ?? '—'} records
          </p>
        </div>
        <div>
          <input ref={fileRef} type="file" accept=".csv" className="hidden" onChange={handleUpload} />
          <button
            onClick={() => fileRef.current?.click()}
            disabled={uploading}
            className="flex items-center gap-2 bg-emerald-700 hover:bg-emerald-800
                       disabled:opacity-50 text-white px-4 py-2 rounded-lg
                       text-sm font-medium transition-colors"
          >
            {uploading ? <Spinner size={4} /> : <Upload className="w-4 h-4" />}
            Upload CSV
          </button>
        </div>
      </div>

      {/* Upload feedback */}
      {uploadMsg && (
        <div className={`flex items-center gap-2 p-3 rounded-lg text-sm border
          ${uploadMsg.ok
            ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-300 dark:border-emerald-800'
            : 'bg-red-50   text-red-700   border-red-200   dark:bg-red-900/30   dark:text-red-300   dark:border-red-800'
          }`}>
          {uploadMsg.ok
            ? <CheckCircle className="w-4 h-4 shrink-0"/>
            : <AlertCircle className="w-4 h-4 shrink-0"/>
          }
          {uploadMsg.msg}
        </div>
      )}

      {/* Filters */}
      <form onSubmit={handleSearch} className="card flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[160px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-stone-400 dark:text-stone-500" />
          <input className="field w-full pl-9" placeholder="Event type…"
            value={eventType} onChange={e => setEType(e.target.value)} />
        </div>
        <div className="relative flex-1 min-w-[140px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-stone-400 dark:text-stone-500" />
          <input className="field w-full pl-9" placeholder="Source IP…"
            value={sourceIp} onChange={e => setSrcIp(e.target.value)} />
        </div>
        <select
          className="field"
          value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <button type="submit"
          className="bg-emerald-700 hover:bg-emerald-800 text-white px-4 py-2
                     rounded-lg text-sm font-medium transition-colors">
          Search
        </button>
      </form>

      {/* Table */}
      <div className="card overflow-x-auto">
        {loading ? (
          <div className="flex justify-center py-10"><Spinner size={8} /></div>
        ) : (
          <>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-stone-400 dark:text-stone-500
                               border-b border-stone-200 dark:border-stone-800
                               text-xs uppercase tracking-wide">
                  {['Timestamp','Source IP','Event Type','Severity','Failed Logins','Asset','Label'].map(h => (
                    <th key={h} className="text-left py-3 pr-3 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data?.items.map(log => (
                  <tr key={log.id} className="trow">
                    <td className="py-2 pr-3 text-stone-500 dark:text-stone-400 font-mono text-xs">{log.timestamp?.slice(0,19) ?? '—'}</td>
                    <td className="py-2 pr-3 text-stone-600 dark:text-stone-300 font-mono text-xs">{log.source_ip ?? '—'}</td>
                    <td className="py-2 pr-3 text-stone-800 dark:text-stone-100">{log.event_type}</td>
                    <td className="py-2 pr-3"><SeverityBadge severity={log.severity} /></td>
                    <td className="py-2 pr-3 text-center text-stone-600 dark:text-stone-300">{log.failed_login_count}</td>
                    <td className="py-2 pr-3 text-stone-500 dark:text-stone-400 text-xs">{log.affected_asset ?? '—'}</td>
                    <td className="py-2">
                      {log.label === 'suspicious'
                        ? <span className="text-xs text-orange-700 bg-orange-100 dark:text-orange-400 dark:bg-orange-900/30 px-2 py-0.5 rounded">{log.label}</span>
                        : <span className="text-xs text-emerald-700 bg-emerald-100 dark:text-emerald-400 dark:bg-emerald-900/30 px-2 py-0.5 rounded">{log.label ?? '—'}</span>
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {data?.items.length === 0 && (
              <div className="text-center py-10 text-stone-400 dark:text-stone-500">
                No logs found. Upload a CSV file to get started.
              </div>
            )}

            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4 pt-4
                              border-t border-stone-200 dark:border-stone-800">
                <span className="text-sm text-stone-500 dark:text-stone-400">
                  Page {page} of {totalPages}
                </span>
                <div className="flex gap-2">
                  <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}
                    className="p-1.5 rounded bg-stone-100 text-stone-500 hover:bg-stone-200
                               dark:bg-stone-800 dark:text-stone-400 dark:hover:bg-stone-700 disabled:opacity-40">
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}
                    className="p-1.5 rounded bg-stone-100 text-stone-500 hover:bg-stone-200
                               dark:bg-stone-800 dark:text-stone-400 dark:hover:bg-stone-700 disabled:opacity-40">
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
