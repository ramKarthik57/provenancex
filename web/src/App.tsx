import { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';
import { PipelineTab } from './components/PipelineTab';
import { BenchmarkTab, Scenario } from './components/BenchmarkTab';
import { DeltaTab } from './components/DeltaTab';
import { BundleTab } from './components/BundleTab';

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'benchmark' | 'delta' | 'bundle'>('overview');
  const [scenarios, setScenarios] = useState<Scenario[]>([]);

  useEffect(() => {
    fetch('/api/v1/scenarios')
      .then((res) => (res.ok ? res.json() : Promise.reject()))
      .then((data) => setScenarios(data))
      .catch(() => {
        setScenarios([
          { id: 'EXP-01', name: 'Source Code Tampering', category: 'Source Integrity', description: 'Uncommitted backdoor modifications in repository.', targetLayer: 'SOURCE', expectedVerdict: 'REJECTED', expectedBreakLayer: 'SOURCE' },
          { id: 'EXP-02', name: 'Dependency Substitution & Typosquatting', category: 'Dependency Integrity', description: 'Lockfile points to hijacked dependency version.', targetLayer: 'DEPENDENCIES', expectedVerdict: 'REJECTED', expectedBreakLayer: 'DEPENDENCIES' },
          { id: 'EXP-03', name: 'Unpinned Floating Dependencies', category: 'Dependency Integrity', description: 'Unpinned dependencies without deterministic lockfile.', targetLayer: 'DEPENDENCIES', expectedVerdict: 'REJECTED', expectedBreakLayer: 'DEPENDENCIES' },
          { id: 'EXP-04', name: 'Build Process Injection', category: 'Build Execution', description: 'In-flight execution spawns unauthorized shell exfiltration.', targetLayer: 'PROCESS', expectedVerdict: 'REJECTED', expectedBreakLayer: 'PROCESS' },
          { id: 'EXP-05', name: 'Build Stage Execution Failure', category: 'Build Execution', description: 'Compromised build script exits with error.', targetLayer: 'BUILD', expectedVerdict: 'REJECTED', expectedBreakLayer: 'BUILD' },
          { id: 'EXP-06', name: 'Unexpected Filesystem Input Injection', category: 'Filesystem Boundary', description: 'Hidden untracked secret payload introduced to build.', targetLayer: 'FILESYSTEM', expectedVerdict: 'REJECTED', expectedBreakLayer: 'FILESYSTEM' },
          { id: 'EXP-07', name: 'Unauthorized Network Egress', category: 'Network Egress', description: 'Build opens egress sockets to unapproved remote host.', targetLayer: 'NETWORK', expectedVerdict: 'REJECTED', expectedBreakLayer: 'NETWORK' },
          { id: 'EXP-08', name: 'SBOM Component Discrepancy', category: 'Attestation / SBOM', description: 'Declared SBOM omits packages resolved during build.', targetLayer: 'SBOM', expectedVerdict: 'REJECTED', expectedBreakLayer: 'SBOM' },
          { id: 'EXP-09', name: 'Provenance Subject Contradiction', category: 'Provenance & SLSA', description: 'in-toto statement claims differing binary SHA-256.', targetLayer: 'PROVENANCE', expectedVerdict: 'REJECTED', expectedBreakLayer: 'PROVENANCE' },
          { id: 'EXP-10', name: 'Cryptographic Signature Forgery', category: 'Digital Signature', description: 'Cryptographic signature assertion invalid.', targetLayer: 'SIGNATURE', expectedVerdict: 'REJECTED', expectedBreakLayer: 'SIGNATURE' },
        ]);
      });
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-sky-500/30 selection:text-sky-200">
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-gradient-to-tr from-sky-500 to-indigo-600 rounded-xl text-white shadow-lg shadow-sky-500/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <span className="font-extrabold text-lg tracking-tight bg-gradient-to-r from-sky-400 via-indigo-300 to-indigo-400 bg-clip-text text-transparent">
                ProvenanceX
              </span>
              <span className="ml-2.5 text-[11px] font-mono font-medium px-2 py-0.5 rounded-full bg-slate-800 text-sky-400 border border-slate-700/60">
                v0.1.0 • Research Suite
              </span>
            </div>
          </div>

          <nav className="flex items-center space-x-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800">
            {(['overview', 'benchmark', 'delta', 'bundle'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-medium capitalize transition-all ${
                  activeTab === tab
                    ? 'bg-sky-500 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                {tab === 'overview' ? 'Verification Pipeline' : tab === 'benchmark' ? 'Attack Benchmarks (10)' : tab === 'delta' ? 'Build Delta' : 'Air-Gapped Bundle'}
              </button>
            ))}
          </nav>

          <div className="flex items-center space-x-3 text-xs text-slate-400 font-mono">
            <span className="flex items-center space-x-1.5 bg-emerald-950/40 border border-emerald-500/30 px-2.5 py-1 rounded-full text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>API Active :8080</span>
            </span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 flex-1 w-full">
        {activeTab === 'overview' && <PipelineTab />}
        {activeTab === 'benchmark' && <BenchmarkTab scenarios={scenarios} setScenarios={setScenarios} />}
        {activeTab === 'delta' && <DeltaTab />}
        {activeTab === 'bundle' && <BundleTab />}
      </main>

      <footer className="border-t border-slate-800/80 bg-slate-900/40 py-4 text-center text-xs text-slate-500">
        ProvenanceX • Cross-Layer Software Supply-Chain Integrity Verification Framework • MIT / Apache-2.0
      </footer>
    </div>
  );
}

