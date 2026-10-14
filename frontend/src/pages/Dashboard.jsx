import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Activity, Shield, ShieldAlert, Cpu, Lock, Radio } from 'lucide-react';
import StatCard from '../components/StatCard';
import AlertPanel from '../components/AlertPanel';
import AttackGraph from '../components/AttackGraph';
import LogsViewer from '../components/LogsViewer';
import AuditForensics from '../components/AuditForensics';

const Dashboard = () => {
  const [currentView, setCurrentView] = useState('telemetry'); // 'telemetry' | 'forensics'

  const [analysis, setAnalysis] = useState({
    total_files: 0,
    unique_files: 0,
    total_events: 0,
    attack_duration: 0.0,
    timeline: [],
    alert_level: "LOW",
    risk_score: 0,
    summary: "Awaiting connection...",
    attack_detected: false
  });

  const [logs, setLogs] = useState([]);
  const [isLive, setIsLive] = useState(false);
  const [auditStatus, setAuditStatus] = useState({ verified: true, count: 0 });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [analysisRes, logsRes] = await Promise.all([
          axios.get('http://localhost:3600/analysis'),
          axios.get('http://localhost:3600/logs')
        ]);

        setAnalysis(analysisRes.data);
        setLogs(logsRes.data);
        setIsLive(true);
      } catch (error) {
        console.error("Backend connection failed", error);
        setIsLive(false);
      }
    };

    const fetchAuditSummary = async () => {
      try {
        const res = await axios.get('http://localhost:3600/audit/records');
        setAuditStatus({
          verified: res.data?.verification?.verified ?? true,
          count: res.data?.count ?? 0
        });
      } catch (e) {
        // Silently tolerate if audit log endpoint is loading
      }
    };

    fetchData();
    fetchAuditSummary();

    const interval = setInterval(() => {
      fetchData();
      fetchAuditSummary();
    }, 2500);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen h-screen w-full flex flex-col bg-slate-950 text-slate-200 overflow-hidden px-4 py-3">
      {/* Header section */}
      <div className="flex flex-wrap items-center justify-between mb-3 pb-2 border-b border-slate-800 gap-2 shrink-0">
        <div className="flex items-center">
          <Activity className="w-6 h-6 mr-2 text-cyan-500" />
          <div>
            <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
              Security Operations Center
            </h1>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest leading-none">
              Real-time threat telemetry & cryptographic forensics
            </p>
          </div>
        </div>

        {/* Center: Module Navigation Tabs */}
        <div className="flex bg-slate-900 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setCurrentView('telemetry')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-[11px] font-bold uppercase tracking-wider transition-all ${
              currentView === 'telemetry'
                ? 'bg-cyan-600 text-white shadow-sm shadow-cyan-900/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Threat Telemetry</span>
          </button>

          <button
            onClick={() => setCurrentView('forensics')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-[11px] font-bold uppercase tracking-wider transition-all ${
              currentView === 'forensics'
                ? 'bg-indigo-600 text-white shadow-sm shadow-indigo-900/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Cryptographic Forensics</span>
            {auditStatus.count > 0 && (
              <span className={`ml-1 text-[9px] px-1.5 py-0.2 rounded-full font-mono ${
                auditStatus.verified ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
              }`}>
                {auditStatus.count}
              </span>
            )}
          </button>
        </div>

        {/* Right Status Badges */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center bg-slate-900 px-3 py-1 rounded-full border border-slate-800">
            <span className="relative flex h-2 w-2 mr-2">
              {isLive && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
              <span className={`relative inline-flex rounded-full h-2 w-2 ${isLive ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
            </span>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
              {isLive ? 'System Online' : 'System Offline'}
            </span>
          </div>
        </div>
      </div>

      {/* Main View Area */}
      {currentView === 'telemetry' ? (
        <div className="flex-1 flex flex-col gap-3 min-h-0">
          
          {/* Top Row: Metrics and Status Summary */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-3 h-auto shrink-0">
            <div className="lg:col-span-4">
              <AlertPanel alertLevel={analysis.alert_level} summary={analysis.summary} compact />
            </div>
          </div>

          {/* Second Row: Detailed Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 shrink-0">
            <StatCard
              title="Files Affected"
              value={analysis.unique_files}
              highlight={analysis.unique_files > 0}
              icon={<Shield className="w-4 h-4 text-cyan-500" />}
              compact
            />
            <StatCard
              title="Encryption Events"
              value={analysis.total_events}
              highlight={analysis.total_events > 0}
              icon={<ShieldAlert className="w-4 h-4 text-rose-500" />}
              compact
            />
            <StatCard
              title="Attack Duration"
              value={analysis.attack_duration}
              subtext="sec"
              icon={<Cpu className="w-4 h-4 text-amber-500" />}
              compact
            />
            <StatCard
              title="Burst Intensity"
              value={analysis.timeline.length > 0 ? Math.max(...analysis.timeline.map(t => t.count)) : 0}
              subtext="ops/s"
              compact
            />
          </div>

          {/* Third Row: Visualization and Logs */}
          <div className="flex-1 grid grid-cols-1 lg:grid-cols-5 gap-3 min-h-0">
            <div className="lg:col-span-2 flex flex-col min-h-0">
              <AttackGraph data={analysis.timeline} />
            </div>
            <div className="lg:col-span-3 flex flex-col min-h-0">
              <LogsViewer logs={logs} />
            </div>
          </div>

        </div>
      ) : (
        <div className="flex-1 flex flex-col min-h-0">
          <AuditForensics />
        </div>
      )}
    </div>
  );
};

export default Dashboard;
