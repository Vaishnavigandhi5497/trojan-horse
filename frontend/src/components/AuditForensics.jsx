import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  XCircle, 
  RefreshCw, 
  Lock, 
  HelpCircle,
  Sliders,
  X,
  FileCheck2,
  FileWarning,
  Hash,
  AlertTriangle,
  FileText
} from 'lucide-react';
import { format, parseISO } from 'date-fns';

const API_BASE = 'http://localhost:3600';

const AuditForensics = () => {
  const [activeTab, setActiveTab] = useState('live'); // 'live' | 'demo'
  
  // Live audit log state
  const [liveData, setLiveData] = useState({
    records: [],
    verification: null,
    count: 0
  });
  const [liveLoading, setLiveLoading] = useState(false);

  // Tampering demo state
  const [demoData, setDemoData] = useState({
    records: [],
    verification: null,
    description: '',
    tamperedActions: []
  });
  const [demoLoading, setDemoLoading] = useState(false);

  // Verification Report Modal (Popup) State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalReport, setModalReport] = useState(null);
  const [modalTarget, setModalTarget] = useState('live'); // 'live' | 'demo'

  // Fetch live audit records (data only, no intrusive banner)
  const fetchLiveAudit = async () => {
    setLiveLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/audit/records`);
      setLiveData({
        records: res.data.records || [],
        verification: res.data.verification || null,
        count: res.data.count || 0
      });
    } catch (err) {
      console.error('Failed to fetch audit records', err);
    } finally {
      setLiveLoading(false);
    }
  };

  // Run live verification and OPEN POPUP
  const handleVerifyLive = async () => {
    setLiveLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/audit/verify`);
      setLiveData(prev => ({ ...prev, verification: res.data }));
      setModalReport(res.data);
      setModalTarget('live');
      setIsModalOpen(true);
    } catch (err) {
      console.error('Verification failed', err);
    } finally {
      setLiveLoading(false);
    }
  };

  // Fetch demo sandbox chain
  const fetchDemoData = async () => {
    setDemoLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/audit/demo`);
      setDemoData(prev => ({
        ...prev,
        records: res.data.records || [],
        verification: res.data.verification || null
      }));
    } catch (err) {
      console.error('Failed to fetch demo data', err);
    } finally {
      setDemoLoading(false);
    }
  };

  // Run demo verification and OPEN POPUP
  const handleVerifyDemo = async () => {
    setDemoLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/audit/demo/verify`);
      setDemoData(prev => ({ ...prev, verification: res.data }));
      setModalReport(res.data);
      setModalTarget('demo');
      setIsModalOpen(true);
    } catch (err) {
      console.error('Verification failed', err);
    } finally {
      setDemoLoading(false);
    }
  };

  // Reset demo sandbox
  const handleResetDemo = async () => {
    setDemoLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/audit/demo/reset`);
      setDemoData({
        records: res.data.records || [],
        verification: res.data.verification || null,
        description: 'Clean pristine state restored.',
        tamperedActions: []
      });
      // Also update modal report if open
      if (isModalOpen && modalTarget === 'demo') {
        setModalReport(res.data.verification);
      }
    } catch (err) {
      console.error('Reset failed', err);
    } finally {
      setDemoLoading(false);
    }
  };

  // Trigger tampering action on demo sandbox (supports multiple cumulative tampers)
  const handleTamperDemo = async (tamperType, targetIndex = 1, actionLabel) => {
    setDemoLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/audit/demo/tamper`, {
        tamper_type: tamperType,
        target_index: targetIndex
      });
      setDemoData(prev => ({
        records: res.data.records || [],
        verification: res.data.verification || null,
        description: res.data.description,
        tamperedActions: [...prev.tamperedActions, actionLabel]
      }));
      // If modal is currently open, dynamically update it with new threats!
      if (isModalOpen && modalTarget === 'demo') {
        setModalReport(res.data.verification);
      }
    } catch (err) {
      console.error('Tamper simulation failed', err);
    } finally {
      setDemoLoading(false);
    }
  };

  // Initial load
  useEffect(() => {
    fetchLiveAudit();
    fetchDemoData();
  }, []);

  const formatTimestamp = (ts) => {
    if (!ts) return 'N/A';
    try {
      return format(parseISO(ts), 'HH:mm:ss.SS');
    } catch (e) {
      return ts;
    }
  };

  const currentRecords = activeTab === 'live' ? liveData.records : demoData.records;
  const currentVerification = activeTab === 'live' ? liveData.verification : demoData.verification;

  // Identify all tampered record indices
  const invalidIndices = new Set(
    currentVerification?.issues ? currentVerification.issues.map(i => i.index) : (
      currentVerification && !currentVerification.verified && currentVerification.invalid_index !== null ? [currentVerification.invalid_index] : []
    )
  );

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0 text-slate-200 relative">
      
      {/* Top Controls Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0">
        
        {/* Left: Chain Stats Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
                {activeTab === 'live' ? 'Live Telemetry Audit Log' : 'Demo Sandbox Audit Log'}
              </div>
              <div className="text-xl font-mono font-black text-slate-100">
                {currentRecords?.length || 0} <span className="text-xs font-normal text-slate-500">records</span>
              </div>
            </div>
          </div>

          <div className="text-right">
            <div className="text-[9px] uppercase font-bold text-slate-500 tracking-wider">Genesis Link</div>
            <div className="text-[10px] font-mono text-cyan-400">0000...0000</div>
          </div>
        </div>

        {/* Center: Audit Engine Info */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex items-center justify-between">
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Cryptographic Standard</div>
            <div className="text-xs font-mono font-bold text-emerald-400 mt-0.5">SHA-256 Hash Chaining</div>
            <div className="text-[9px] text-slate-500">Deterministic UTF-8 Canonicalization</div>
          </div>
          <div className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300">
            <Hash className="w-3.5 h-3.5 text-cyan-400" />
            <span>256-bit Digest</span>
          </div>
        </div>

        {/* Right: Mode Switcher & Prominent Verify Button */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-2.5 flex items-center justify-between">
          <div className="flex bg-slate-950 p-0.5 rounded-lg border border-slate-800">
            <button
              onClick={() => setActiveTab('live')}
              className={`px-3 py-1.5 rounded-md text-[10px] font-bold uppercase tracking-wider transition-colors ${
                activeTab === 'live' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Live Production
            </button>
            <button
              onClick={() => setActiveTab('demo')}
              className={`px-3 py-1.5 rounded-md text-[10px] font-bold uppercase tracking-wider transition-colors ${
                activeTab === 'demo' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Tampering Sandbox
            </button>
          </div>

          <button
            onClick={activeTab === 'live' ? handleVerifyLive : handleVerifyDemo}
            disabled={liveLoading || demoLoading}
            className="flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-wider bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-md shadow-cyan-950 transition-all disabled:opacity-50 cursor-pointer"
          >
            <ShieldCheck className={`w-4 h-4 ${liveLoading || demoLoading ? 'animate-spin' : ''}`} />
            <span>Verify Integrity</span>
          </button>
        </div>

      </div>

      {/* Sandbox Controls (Only shown in Demo Tab) */}
      {activeTab === 'demo' && (
        <div className="bg-indigo-950/20 border border-indigo-800/50 rounded-xl p-3 shrink-0">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <Sliders className="w-4 h-4 text-indigo-400" />
              <span className="text-[11px] font-bold uppercase tracking-wider text-indigo-300">
                Safe Tampering Demonstration Sandbox
              </span>
            </div>
            <span className="text-[9px] text-indigo-400/80 uppercase font-mono">
              ⚠️ Disposable test dataset — changes never affect live audit logs
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => handleTamperDemo('modify_event', 1, 'Altered Record #2 Event Payload')}
              className="px-2.5 py-1 text-[10px] font-bold rounded bg-slate-800 hover:bg-slate-700 text-amber-300 border border-amber-600/40 transition-colors"
            >
              1. Alter Payload (Record #2)
            </button>
            <button
              onClick={() => handleTamperDemo('modify_hash', 2, 'Corrupted Record #3 Stored Hash')}
              className="px-2.5 py-1 text-[10px] font-bold rounded bg-slate-800 hover:bg-slate-700 text-rose-300 border border-rose-600/40 transition-colors"
            >
              2. Corrupt Stored Hash (Record #3)
            </button>
            <button
              onClick={() => handleTamperDemo('delete_record', 1, 'Deleted Record #2 (Chain Gap)')}
              className="px-2.5 py-1 text-[10px] font-bold rounded bg-slate-800 hover:bg-slate-700 text-purple-300 border border-purple-600/40 transition-colors"
            >
              3. Delete Record #2 (Break Link)
            </button>
            <button
              onClick={() => handleTamperDemo('reorder_records', 1, 'Swapped Order of Records #2 and #3')}
              className="px-2.5 py-1 text-[10px] font-bold rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-600/40 transition-colors"
            >
              4. Reorder Records #2 & #3
            </button>
            
            <div className="ml-auto flex items-center space-x-2">
              <button
                onClick={handleVerifyDemo}
                className="px-3 py-1 text-[10px] font-bold rounded bg-blue-600 hover:bg-blue-500 text-white transition-colors flex items-center space-x-1 shadow-sm"
              >
                <ShieldCheck className="w-3 h-3" />
                <span>Verify Demo Chain</span>
              </button>

              <button
                onClick={handleResetDemo}
                className="px-3 py-1 text-[10px] font-bold rounded bg-emerald-700 hover:bg-emerald-600 text-white transition-colors flex items-center space-x-1"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Reset Clean Chain</span>
              </button>
            </div>
          </div>

          {demoData.tamperedActions.length > 0 && (
            <div className="mt-2 text-[10px] text-amber-300 bg-slate-900/90 px-2.5 py-1.5 rounded border border-amber-900/40 flex items-center justify-between">
              <div>
                <span className="font-bold uppercase tracking-wider text-amber-400">Tampering Actions Applied ({demoData.tamperedActions.length}):</span>{' '}
                <span className="font-mono text-slate-300">{demoData.tamperedActions.join(' ➔ ')}</span>
              </div>
              <span className="text-[9px] text-slate-400">Click "Verify Demo Chain" to inspect threats</span>
            </div>
          )}
        </div>
      )}

      {/* Main Content: Table of Audit Records */}
      <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col min-h-0">
        <div className="px-4 py-2 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <h3 className="text-slate-400 text-[10px] font-bold uppercase tracking-[0.2em]">
              {activeTab === 'live' ? 'Live Telemetry Audit Log' : 'Simulated Demo Audit Log'}
            </h3>
          </div>
          <span className="text-[9px] text-slate-500 font-mono">
            {currentRecords.length} Total Chained Blocks
          </span>
        </div>

        <div className="overflow-x-auto overflow-y-auto flex-1 custom-scrollbar">
          {currentRecords.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-8 text-center text-slate-500">
              <FileText className="w-8 h-8 mb-2 opacity-50" />
              <p className="text-xs font-mono uppercase tracking-widest">No audit records in chain</p>
              <p className="text-[10px] text-slate-600 mt-1">Execute the trojan simulation or quick scan to record events</p>
            </div>
          ) : (
            <table className="w-full text-left text-[11px] text-slate-400 border-collapse">
              <thead className="bg-slate-950 sticky top-0 z-10 text-[9px] uppercase text-slate-500 font-bold tracking-tighter">
                <tr>
                  <th className="px-3 py-2 border-b border-slate-800">Record ID</th>
                  <th className="px-3 py-2 border-b border-slate-800">Timestamp</th>
                  <th className="px-3 py-2 border-b border-slate-800">Operation</th>
                  <th className="px-3 py-2 border-b border-slate-800">Status</th>
                  <th className="px-3 py-2 border-b border-slate-800">Target / File</th>
                  <th className="px-3 py-2 border-b border-slate-800">Previous Hash</th>
                  <th className="px-3 py-2 border-b border-slate-800">Record SHA-256 Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {currentRecords.map((rec, index) => {
                  const isTampered = invalidIndices.has(index);
                  const isGenesis = index === 0;

                  return (
                    <tr 
                      key={rec.record_id || index} 
                      className={`transition-colors ${
                        isTampered 
                          ? 'bg-rose-950/40 hover:bg-rose-900/50 text-rose-200' 
                          : 'hover:bg-slate-800/30 text-slate-300'
                      }`}
                    >
                      <td className="px-3 py-1.5 whitespace-nowrap font-mono text-[10px] font-bold flex items-center space-x-1.5">
                        {isTampered && <AlertTriangle className="w-3.5 h-3.5 text-rose-400 inline" />}
                        <span className={isTampered ? 'text-rose-300' : 'text-slate-200'}>{rec.record_id}</span>
                      </td>
                      <td className="px-3 py-1.5 whitespace-nowrap font-mono text-[10px] opacity-75">
                        {formatTimestamp(rec.timestamp)}
                      </td>
                      <td className="px-3 py-1.5 whitespace-nowrap font-bold uppercase tracking-tight text-cyan-400">
                        {rec.event_data?.event || 'EVENT'}
                      </td>
                      <td className="px-3 py-1.5 whitespace-nowrap">
                        <span className={`px-1.5 py-0.5 rounded-sm text-[9px] font-black uppercase tracking-tighter ${
                          rec.event_data?.status === 'SUCCESS' ? 'text-green-400 bg-green-900/20' : 'text-red-400 bg-red-900/20'
                        }`}>
                          {rec.event_data?.status || 'OK'}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 font-mono text-[10px] text-slate-400 truncate max-w-xs" title={rec.event_data?.file || ''}>
                        {rec.event_data?.file || rec.event_data?.details || 'N/A'}
                      </td>
                      <td className="px-3 py-1.5 whitespace-nowrap font-mono text-[10px]" title={rec.prev_hash}>
                        <span className={`px-1.5 py-0.5 rounded text-[9px] ${
                          isGenesis ? 'text-slate-500 bg-slate-950' : 'text-slate-400 bg-slate-950 border border-slate-800'
                        }`}>
                          {rec.prev_hash ? `${rec.prev_hash.slice(0, 8)}...${rec.prev_hash.slice(-4)}` : 'NULL'}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 whitespace-nowrap font-mono text-[10px]" title={rec.record_hash}>
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                          isTampered 
                            ? 'text-rose-400 bg-rose-950 border border-rose-800 font-mono animate-pulse' 
                            : 'text-emerald-400 bg-slate-950 border border-slate-800'
                        }`}>
                          {rec.record_hash ? `${rec.record_hash.slice(0, 8)}...${rec.record_hash.slice(-4)}` : 'NULL'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Educational: How Cryptographic Forensics Works & Known Limitations */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3 shrink-0">
        <div className="flex items-center space-x-2 mb-1.5">
          <HelpCircle className="w-4 h-4 text-cyan-400" />
          <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-300">
            How Cryptographic Forensics & Tamper Detection Works
          </h4>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[10px] text-slate-400">
          <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
            <span className="font-bold text-cyan-400 block mb-1">1. SHA-256 Hashing (One-Way)</span>
            Each record's fields are serialized deterministically (sorted keys, compact delimiters) and hashed using SHA-256. The hash is a one-way mathematical fingerprint, not encryption. Modifying even one byte of event data changes the resulting hash entirely.
          </div>

          <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
            <span className="font-bold text-emerald-400 block mb-1">2. Previous-Hash Chaining</span>
            Every record embeds the previous record's SHA-256 hash (<code className="text-emerald-300 font-mono">prev_hash</code>), linked back to the fixed genesis value. This links records together in an order-dependent cryptographically validated chain.
          </div>

          <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
            <span className="font-bold text-amber-400 block mb-1">3. Tamper Detection & Limitations</span>
            Deleting, editing, or reordering records breaks subsequent links or hash checks.
            <div className="mt-1 text-slate-500 text-[9px] border-t border-slate-800 pt-1">
              <strong>Limitation:</strong> Hash chaining provides <em>tamper-evidence</em>, but not <em>immutable storage</em>. An attacker who can rewrite the entire disk and recompute every hash could forge a new chain. Signatures or external anchoring are needed for origin proof.
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* FORENSIC VERIFICATION REPORT MODAL (POPUP TRIGGERED BY "VERIFY INTEGRITY") */}
      {/* ========================================================================= */}
      {isModalOpen && modalReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[90vh] animate-in fade-in zoom-in-95 duration-150">
            
            {/* Modal Header */}
            <div className="px-5 py-3.5 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
                <div>
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-100">
                    Cryptographic Integrity Audit Report
                  </h3>
                  <p className="text-[10px] text-slate-500">
                    {modalTarget === 'live' ? 'Live Telemetry Production Log' : 'Disposable Sandbox Test Dataset'}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 overflow-y-auto custom-scrollbar flex flex-col gap-4">
              
              {/* Verdict Banner */}
              <div className={`p-4 rounded-xl border flex items-center space-x-3.5 ${
                modalReport.verified 
                  ? 'bg-emerald-950/30 border-emerald-700/50 text-emerald-300' 
                  : 'bg-rose-950/40 border-rose-700/60 text-rose-300'
              }`}>
                {modalReport.verified ? (
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 shrink-0" />
                ) : (
                  <ShieldAlert className="w-8 h-8 text-rose-400 shrink-0" />
                )}
                <div>
                  <div className="text-sm font-black uppercase tracking-wider">
                    {modalReport.verified 
                      ? 'INTEGRITY VERIFIED: ALL HASHES & CHAIN LINKS VALID' 
                      : `TAMPERING DETECTED: ${modalReport.total_threats || 1} THREAT(S) IDENTIFIED`}
                  </div>
                  <p className="text-[11px] text-slate-300 mt-0.5">
                    {modalReport.message}
                  </p>
                </div>
              </div>

              {/* Inspection Steps Checklist */}
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 text-[11px]">
                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2">
                  Forensic Chain Verification Checklist
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <div className="flex items-center space-x-2 text-slate-300">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Genesis Previous-Hash (`0`*64) Verified</span>
                  </div>
                  <div className="flex items-center space-x-2 text-slate-300">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Deterministic Canonical Serialization</span>
                  </div>
                  <div className="flex items-center space-x-2 text-slate-300">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Recalculated SHA-256 for {modalReport.total_records} records</span>
                  </div>
                  <div className="flex items-center space-x-2 text-slate-300">
                    {modalReport.verified ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                    )}
                    <span>Link & Payload Consistency Check</span>
                  </div>
                </div>
              </div>

              {/* Detected Threats Breakdown (Shows ALL Threats!) */}
              {!modalReport.verified && modalReport.issues && modalReport.issues.length > 0 && (
                <div className="flex flex-col gap-2">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-rose-400 flex items-center space-x-1.5">
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    <span>Detected Security Violations ({modalReport.issues.length})</span>
                  </div>

                  <div className="space-y-2">
                    {modalReport.issues.map((issue, idx) => (
                      <div key={idx} className="bg-rose-950/30 border border-rose-900/60 p-3 rounded-xl text-[11px]">
                        <div className="flex items-center justify-between font-bold text-rose-300 mb-1">
                          <span>Threat #{idx + 1}: {issue.error_type}</span>
                          <span className="font-mono text-[10px] bg-rose-950 px-2 py-0.5 rounded border border-rose-800">
                            Record: {issue.record_id} (Index {issue.index})
                          </span>
                        </div>
                        <p className="text-slate-300 text-[10px]">
                          {issue.details}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>

            {/* Modal Footer */}
            <div className="px-5 py-3 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
              <span className="text-[10px] text-slate-500 font-mono">
                Verification Algorithm: Independent Re-computation
              </span>
              <button
                onClick={() => setIsModalOpen(false)}
                className="px-4 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
              >
                Close Report
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};

export default AuditForensics;
