import { useEffect, useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';
import { AlertTriangle, FileText, Link2, Shield, Cpu, TrendingUp } from 'lucide-react';
import { getDashboard } from '../services/api';
import type { DashboardSummary } from '../types';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import Spinner from '../components/Spinner';
import { useTheme } from '../hooks/useTheme';

/* Nature palette — earthy, warm, no blue */
const CHART_COLORS = ['#059669','#d97706','#b45309','#16a34a','#7c3aed','#ea580c'];

export default function Dashboard() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const tooltipStyle = isDark
    ? { background: '#1c1917', border: '1px solid #44403c', color: '#f5f5f4' }
    : { background: '#ffffff', border: '1px solid #e7e5e4', color: '#1c1917' };
  const tickColor = isDark ? '#a8a29e' : '#78716c';

  const [data, setData]    = useState<DashboardSummary | null>(null);
  const [loading, setLoad] = useState(true);
  const [error, setError]  = useState<string | null>(null);

  useEffect(() => {
    getDashboard()
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoad(false));
  }, []);

  if (loading) return <div className="flex justify-center items-center h-64"><Spinner size={10} /></div>;
  if (error)   return <div className="card text-red-500">{error}</div>;
  if (!data)   return null;

  const eventData = Object.entries(data.event_type_distribution)
    .map(([name, value]) => ({ name: name.replace(/_/g, ' '), value }))
    .sort((a, b) => b.value - a.value).slice(0, 8);

  const severityData = Object.entries(data.severity_distribution)
    .map(([name, value]) => ({ name, value }));

  const methodData = Object.entries(data.detection_method_distribution)
    .map(([name, value]) => ({ name, value }));

  const mm = data.model_metrics;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-stone-900 dark:text-stone-100">Dashboard</h1>
        <p className="text-stone-500 dark:text-stone-400 text-sm mt-1">
          Live security analytics — all data from API
        </p>
      </div>

      {/* Stat cards — earthy icon colours */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard label="Total Logs"          value={data.total_logs.toLocaleString()}      icon={<FileText      className="w-5 h-5"/>} color="text-teal-600"    />
        <StatCard label="Suspicious Alerts"   value={data.total_alerts.toLocaleString()}    icon={<AlertTriangle className="w-5 h-5"/>} color="text-orange-600"  />
        <StatCard label="Potential Incidents" value={data.total_incidents.toLocaleString()}  icon={<Link2         className="w-5 h-5"/>} color="text-amber-700"   />
        <StatCard label="Critical Alerts"     value={data.critical_alerts.toLocaleString()} icon={<Shield        className="w-5 h-5"/>} color="text-red-600"     />
      </div>

      {/* ML model card */}
      {mm && (
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <Cpu className="text-emerald-600 w-5 h-5" />
            <h2 className="font-semibold text-stone-900 dark:text-stone-100">
              ML Model: {mm.best_model}
            </h2>
            {data.model_loaded
              ? <span className="text-xs text-emerald-700 bg-emerald-100 dark:text-emerald-400 dark:bg-emerald-900/30 px-2 py-0.5 rounded-full">Loaded</span>
              : <span className="text-xs text-amber-700  bg-amber-100  dark:text-amber-400  dark:bg-amber-900/30  px-2 py-0.5 rounded-full">Not loaded</span>
            }
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {[
              { label: 'Accuracy',   value: mm.accuracy },
              { label: 'F1 (Susp.)', value: mm.f1_suspicious },
              { label: 'Recall',     value: mm.recall_suspicious },
              { label: 'Precision',  value: mm.precision_suspicious },
              { label: 'FPR',        value: mm.false_positive_rate },
            ].map(m => (
              <div key={m.label} className="bg-stone-100 dark:bg-stone-800 rounded-lg p-3 text-center">
                <div className="text-xl font-bold text-emerald-700 dark:text-emerald-400">
                  {(m.value * 100).toFixed(1)}%
                </div>
                <div className="text-xs text-stone-500 dark:text-stone-400 mt-1">{m.label}</div>
              </div>
            ))}
          </div>
          <p className="text-xs text-stone-400 dark:text-stone-600 mt-3">
            * 100% metrics reflect deterministic synthetic labels — real-world performance will differ.
          </p>
        </div>
      )}

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <h2 className="font-semibold text-stone-900 dark:text-stone-100 mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-emerald-600" /> Event Type Distribution
          </h2>
          {eventData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={eventData} layout="vertical" margin={{ left: 20 }}>
                <XAxis type="number" tick={{ fill: tickColor, fontSize: 11 }} />
                <YAxis type="category" dataKey="name" tick={{ fill: tickColor, fontSize: 10 }} width={120} />
                <Tooltip contentStyle={tooltipStyle} />
                {/* forest green bars */}
                <Bar dataKey="value" fill="#059669" radius={[0,4,4,0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-stone-400 dark:text-stone-500 text-sm text-center py-10">
              No data yet — upload logs or run detection
            </div>
          )}
        </div>

        <div className="card">
          <h2 className="font-semibold text-stone-900 dark:text-stone-100 mb-4">
            Severity Distribution
          </h2>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name"
                     cx="50%" cy="50%" outerRadius={80} label>
                  {severityData.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
                <Legend wrapperStyle={{ color: tickColor }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-stone-400 dark:text-stone-500 text-sm text-center py-10">No data yet</div>
          )}
        </div>
      </div>

      {/* Detection method breakdown */}
      {methodData.length > 0 && (
        <div className="card">
          <h2 className="font-semibold text-stone-900 dark:text-stone-100 mb-4">
            Detection Method Breakdown
          </h2>
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={methodData}>
              <XAxis dataKey="name" tick={{ fill: tickColor, fontSize: 12 }} />
              <YAxis tick={{ fill: tickColor, fontSize: 11 }} />
              <Tooltip contentStyle={tooltipStyle} />
              {/* warm amber bars */}
              <Bar dataKey="value" fill="#d97706" radius={[4,4,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent alerts table */}
      {data.recent_alerts.length > 0 && (
        <div className="card overflow-x-auto">
          <h2 className="font-semibold text-stone-900 dark:text-stone-100 mb-4">Recent Alerts</h2>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-stone-400 dark:text-stone-500
                             border-b border-stone-200 dark:border-stone-800
                             text-xs uppercase tracking-wide">
                {['Timestamp','Event Type','Severity','Source IP','Asset','Method'].map(h => (
                  <th key={h} className="text-left pb-2 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.recent_alerts.map(a => (
                <tr key={a.alert_id} className="trow">
                  <td className="py-2 text-stone-500 dark:text-stone-400 font-mono text-xs">{a.timestamp?.slice(0,19)}</td>
                  <td className="py-2 text-stone-800 dark:text-stone-100">{a.event_type}</td>
                  <td className="py-2"><SeverityBadge severity={a.severity} /></td>
                  <td className="py-2 text-stone-500 dark:text-stone-400 font-mono text-xs">{a.source_ip || '—'}</td>
                  <td className="py-2 text-stone-500 dark:text-stone-400 text-xs">{a.affected_asset || '—'}</td>
                  <td className="py-2">
                    {/* teal tag instead of blue */}
                    <span className="tag-mono">{a.detection_method}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
