import { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Logs from './pages/Logs';
import Detection from './pages/Detection';
import Incidents from './pages/Incidents';
import Compliance from './pages/Compliance';
import Reports from './pages/Reports';
import { getHealth } from './services/api';
import { ThemeContext, type Theme } from './hooks/useTheme';
import { Moon, Sun, Wifi, WifiOff } from 'lucide-react';

type Page = 'dashboard' | 'logs' | 'detection' | 'incidents' | 'compliance' | 'reports';

const PAGE_TITLES: Record<Page, string> = {
  dashboard:  'Dashboard',
  logs:       'Security Logs',
  detection:  'Threat Detection',
  incidents:  'Incident Correlation',
  compliance: 'Compliance Mappings',
  reports:    'Security Reports',
};

function getInitialTheme(): Theme {
  if (typeof window === 'undefined') return 'dark';
  const stored = localStorage.getItem('theme') as Theme | null;
  if (stored === 'dark' || stored === 'light') return stored;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export default function App() {
  const [page, setPage]     = useState<Page>('dashboard');
  const [apiOnline, setApi] = useState<boolean | null>(null);
  const [theme, setTheme]   = useState<Theme>(getInitialTheme);

  useEffect(() => {
    const root = document.documentElement;
    theme === 'dark' ? root.classList.add('dark') : root.classList.remove('dark');
    localStorage.setItem('theme', theme);
  }, [theme]);

  const toggle = () => setTheme(t => (t === 'dark' ? 'light' : 'dark'));

  useEffect(() => {
    getHealth()
      .then(() => setApi(true))
      .catch(() => setApi(false));
    // re-check every 30 s
    const id = setInterval(() =>
      getHealth().then(() => setApi(true)).catch(() => setApi(false)), 30000);
    return () => clearInterval(id);
  }, []);

  const pages: Record<Page, React.ReactNode> = {
    dashboard:  <Dashboard />,
    logs:       <Logs />,
    detection:  <Detection />,
    incidents:  <Incidents />,
    compliance: <Compliance />,
    reports:    <Reports />,
  };

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      <div className="flex h-screen overflow-hidden bg-stone-100 dark:bg-stone-950 transition-colors duration-200">

        {/* ── Sidebar ──────────────────────────────────────────── */}
        <Sidebar current={page} onChange={setPage} apiOnline={apiOnline} />

        {/* ── Main column ─────────────────────────────────────── */}
        <div className="flex flex-col flex-1 min-w-0">

          {/* ── Top header bar ────────────────────────────────── */}
          <header className="h-14 shrink-0 flex items-center justify-between
                             px-6 border-b
                             bg-white border-stone-200
                             dark:bg-stone-900 dark:border-stone-800
                             transition-colors duration-200">

            {/* Page title */}
            <h2 className="text-sm font-semibold text-stone-700 dark:text-stone-300 tracking-wide">
              {PAGE_TITLES[page]}
            </h2>

            {/* Right controls */}
            <div className="flex items-center gap-3">

              {/* API status — inline, subtle */}
              {apiOnline !== null && (
                <div className={`flex items-center gap-1.5 text-xs font-medium
                  ${apiOnline
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : 'text-red-500 dark:text-red-400'
                  }`}>
                  {apiOnline
                    ? <Wifi    className="w-3.5 h-3.5" />
                    : <WifiOff className="w-3.5 h-3.5" />
                  }
                  <span className="hidden sm:inline">
                    {apiOnline ? 'API Online' : 'API Offline'}
                  </span>
                </div>
              )}

              {/* Divider */}
              <div className="w-px h-4 bg-stone-200 dark:bg-stone-700" />

              {/* Theme toggle — icon only, clean */}
              <button
                onClick={toggle}
                title={theme === 'dark' ? 'Switch to Light mode' : 'Switch to Dark mode'}
                className="p-1.5 rounded-md text-stone-500 hover:text-stone-800
                           hover:bg-stone-100
                           dark:text-stone-400 dark:hover:text-stone-100
                           dark:hover:bg-stone-800
                           transition-colors"
              >
                {theme === 'dark'
                  ? <Sun  className="w-4 h-4" />
                  : <Moon className="w-4 h-4" />
                }
              </button>
            </div>
          </header>

          {/* ── Page content ─────────────────────────────────── */}
          <main className="flex-1 overflow-y-auto">
            <div className="max-w-7xl mx-auto p-6">
              {pages[page]}
            </div>
          </main>
        </div>

      </div>
    </ThemeContext.Provider>
  );
}
