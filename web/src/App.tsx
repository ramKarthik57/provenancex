import { Shield, GitCommit, Box, Activity, CheckCircle, AlertTriangle, FileText } from 'lucide-react';

export default function App() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-sky-500/10 border border-sky-500/30 rounded-lg text-sky-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-sky-400 to-indigo-400 bg-clip-text text-transparent">
                ProvenanceX
              </span>
              <span className="ml-2 text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                v0.1.0-dev
              </span>
            </div>
          </div>
          <div className="flex items-center space-x-4 text-sm text-slate-400">
            <span className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span className="text-slate-300">System Ready</span>
            </span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Research Banner */}
        <div className="rounded-xl border border-sky-500/20 bg-gradient-to-br from-sky-950/40 via-slate-900 to-indigo-950/20 p-6">
          <h1 className="text-2xl font-bold tracking-tight text-white mb-2">
            Cross-Layer Software Supply-Chain Integrity Verification
          </h1>
          <p className="text-slate-400 text-sm max-w-3xl leading-relaxed">
            ProvenanceX independently investigates whether an artifact's production history is trustworthy,
            reproducible, policy-compliant, and internally consistent across source, dependency, build execution,
            telemetry, and attestation layers.
          </p>
        </div>

        {/* Status Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Repository Integrity</span>
              <GitCommit className="w-4 h-4 text-sky-400" />
            </div>
            <div className="text-xl font-semibold text-white">Clean State</div>
            <div className="text-xs text-slate-500 mt-1 flex items-center space-x-1">
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400 inline" />
              <span>Git tree tracking initialized</span>
            </div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Artifact Hashes</span>
              <Box className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="text-xl font-semibold text-white">SHA-256 / Merkle</div>
            <div className="text-xs text-slate-500 mt-1">Ready for artifact ingestion</div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Correlation Engine</span>
              <Activity className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-xl font-semibold text-white">Rule-Based</div>
            <div className="text-xs text-slate-500 mt-1">Deterministic verdicts</div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Experiments</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-xl font-semibold text-white">10 Benchmarks</div>
            <div className="text-xs text-slate-500 mt-1">Controlled supply-chain suite</div>
          </div>
        </div>

        {/* Architecture & Pipeline Stages */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 space-y-4">
          <div className="flex items-center space-x-2 text-white font-semibold">
            <FileText className="w-5 h-5 text-sky-400" />
            <span>Cross-Layer Verification Pipeline</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2 pt-2">
            {[
              { step: '01', name: 'Source', tag: 'Git Tree' },
              { step: '02', name: 'Deps', tag: 'Lockfile' },
              { step: '03', name: 'Env', tag: 'Fingerprint' },
              { step: '04', name: 'Build', tag: 'Telemetry' },
              { step: '05', name: 'Artifact', tag: 'Merkle' },
              { step: '06', name: 'Provenance', tag: 'SLSA / in-toto' },
              { step: '07', name: 'Decision', tag: 'Deterministic' },
            ].map((item) => (
              <div key={item.step} className="p-3 rounded-lg bg-slate-800/40 border border-slate-700/50 text-center">
                <div className="text-xs font-mono text-sky-400">{item.step}</div>
                <div className="text-sm font-medium text-slate-200 mt-0.5">{item.name}</div>
                <div className="text-[11px] text-slate-400 mt-1">{item.tag}</div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
