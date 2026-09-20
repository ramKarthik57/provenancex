import { useState } from 'react';
import {
  Activity, RefreshCw, AlertTriangle, Box, XCircle, Layers,
  GitCommit, Cpu, Lock
} from 'lucide-react';

export const PIPELINE_LAYERS = [
  { id: 'SOURCE', name: 'Source Code', desc: 'Git commit & tree integrity' },
  { id: 'DEPENDENCIES', name: 'Dependencies', desc: 'Declared manifest packages' },
  { id: 'LOCKFILE', name: 'Lockfile', desc: 'Cryptographic dependency hashes' },
  { id: 'ENVIRONMENT', name: 'Environment', desc: 'Compiler toolchain fingerprint' },
  { id: 'BUILD', name: 'Build Execution', desc: 'Command telemetry & duration' },
  { id: 'PROCESS', name: 'Process Tree', desc: 'Parent-child process monitoring' },
  { id: 'FILESYSTEM', name: 'Filesystem', desc: 'Boundary mutations & input diff' },
  { id: 'NETWORK', name: 'Network Egress', desc: 'Registry allowlist audit' },
  { id: 'ARTIFACT', name: 'Artifact', desc: 'Output digest & Merkle root' },
  { id: 'SBOM', name: 'SBOM', desc: 'CycloneDX / SPDX cross-check' },
  { id: 'PROVENANCE', name: 'Provenance', desc: 'in-toto / SLSA v1.0 claims' },
  { id: 'SIGNATURE', name: 'Signature', desc: 'ECDSA / Ed25519 verification' }
];

export function PipelineTab() {
  const [simulatedLayer, setSimulatedLayer] = useState<string | null>(null);
  const [simulatedVerdict, setSimulatedVerdict] = useState<'TRUSTED' | 'REJECTED' | 'WARNING'>('TRUSTED');

  const resetPipeline = () => {
    setSimulatedLayer(null);
    setSimulatedVerdict('TRUSTED');
  };

  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="rounded-2xl border border-sky-500/20 bg-gradient-to-br from-sky-950/30 via-slate-900 to-indigo-950/30 p-8 shadow-xl">
        <div className="max-w-3xl space-y-3">
          <div className="inline-flex items-center space-x-2 text-xs font-semibold uppercase tracking-wider text-sky-400 bg-sky-500/10 px-3 py-1 rounded-full border border-sky-500/30">
            <Activity className="w-3.5 h-3.5" />
            <span>Cross-Layer Ground Truth Correlator</span>
          </div>
          <h1 className="text-3xl font-black text-white sm:text-4xl">
            Supply-Chain Integrity Verification
          </h1>
          <p className="text-slate-400 text-sm leading-relaxed">
            ProvenanceX correlates observed build telemetry against declared source commits, lockfiles, SBOMs,
            and in-toto provenance. It localizes the earliest causal trust-break layer and delivers explainable verdicts.
          </p>
        </div>

        <div className="mt-6 flex flex-wrap gap-3">
          <button
            onClick={resetPipeline}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-medium rounded-lg border border-slate-700 transition-all flex items-center space-x-2"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Reset Ground Truth (Clean)</span>
          </button>
          <button
            onClick={() => {
              setSimulatedLayer('DEPENDENCIES');
              setSimulatedVerdict('REJECTED');
            }}
            className="px-4 py-2 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 text-xs font-medium rounded-lg border border-rose-500/30 transition-all flex items-center space-x-2"
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Simulate Dependency Attack</span>
          </button>
          <button
            onClick={() => {
              setSimulatedLayer('FILESYSTEM');
              setSimulatedVerdict('REJECTED');
            }}
            className="px-4 py-2 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 text-xs font-medium rounded-lg border border-amber-500/30 transition-all flex items-center space-x-2"
          >
            <Box className="w-3.5 h-3.5" />
            <span>Simulate Injected Input Attack</span>
          </button>
        </div>
      </div>

      {/* Trust-Break Banner */}
      {simulatedLayer && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-5 flex items-start space-x-4">
          <div className="p-2.5 bg-rose-500/20 rounded-lg text-rose-400 mt-0.5 border border-rose-500/30">
            <XCircle className="w-5 h-5" />
          </div>
          <div className="space-y-1 flex-1">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-rose-200">
                Earliest Causal Trust Break: <span className="underline decoration-rose-400">{simulatedLayer} LAYER</span>
              </h3>
              <span className="text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                VERDICT: {simulatedVerdict}
              </span>
            </div>
            <p className="text-xs text-rose-300/80 leading-relaxed">
              Root-cause isolation algorithm localized the break chronologically before subsequent layers executed.
            </p>
          </div>
        </div>
      )}

      {/* 12-Layer Sequence Grid */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-2">
            <Layers className="w-4 h-4 text-sky-400" />
            <span>12-Layer Software Pipeline Sequence</span>
          </h2>
          <span className="text-xs text-slate-500 font-mono">
            Chronological Ordering: Source → Dependencies → Build → Attestation
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {PIPELINE_LAYERS.map((layer, idx) => {
            const isBroken = simulatedLayer === layer.id;
            const isDownstream =
              simulatedLayer &&
              PIPELINE_LAYERS.findIndex((l) => l.id === simulatedLayer) < idx;

            let borderClass = 'border-slate-800 bg-slate-900/50 hover:border-slate-700';
            let statusBadge = (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                VERIFIED
              </span>
            );

            if (isBroken) {
              borderClass = 'border-rose-500 bg-rose-950/40 shadow-lg shadow-rose-950/50 ring-1 ring-rose-500';
              statusBadge = (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/50 font-bold">
                  TRUST BREAK
                </span>
              );
            } else if (isDownstream) {
              borderClass = 'border-slate-800/80 bg-slate-950/60 opacity-60';
              statusBadge = (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  INVALIDATED
                </span>
              );
            }

            return (
              <div
                key={layer.id}
                onClick={() => {
                  setSimulatedLayer(layer.id);
                  setSimulatedVerdict('REJECTED');
                }}
                className={`p-4 rounded-xl border transition-all cursor-pointer flex flex-col justify-between space-y-3 ${borderClass}`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-500">
                    #{String(idx + 1).padStart(2, '0')}
                  </span>
                  {statusBadge}
                </div>

                <div>
                  <div className="text-sm font-bold text-white">{layer.name}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5 leading-snug">{layer.desc}</div>
                </div>

                <div className="text-[10px] text-slate-500 font-mono border-t border-slate-800/60 pt-2 flex items-center justify-between">
                  <span>Plane:</span>
                  <span className="text-slate-400">{layer.id}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-4">
          <div className="flex items-center space-x-2 text-white font-bold text-sm">
            <GitCommit className="w-4 h-4 text-sky-400" />
            <span>Repository State</span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/60 text-slate-400">
              <span>Active Commit</span>
              <span className="font-mono text-slate-200">c0ffee123456...</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60 text-slate-400">
              <span>Working Tree</span>
              <span className="text-emerald-400 font-medium">Clean (No dirty files)</span>
            </div>
            <div className="flex justify-between py-1 text-slate-400">
              <span>Untracked Files</span>
              <span className="text-slate-200">0 files</span>
            </div>
          </div>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-4">
          <div className="flex items-center space-x-2 text-white font-bold text-sm">
            <Cpu className="w-4 h-4 text-indigo-400" />
            <span>Telemetry & Boundary</span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/60 text-slate-400">
              <span>Child Processes</span>
              <span className="font-mono text-slate-200">1 process (go build)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60 text-slate-400">
              <span>Suspicious Shell Calls</span>
              <span className="text-emerald-400 font-medium">0 detected</span>
            </div>
            <div className="flex justify-between py-1 text-slate-400">
              <span>Filesystem Delta</span>
              <span className="text-slate-200">+1 created file</span>
            </div>
          </div>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-4">
          <div className="flex items-center space-x-2 text-white font-bold text-sm">
            <Lock className="w-4 h-4 text-emerald-400" />
            <span>Cryptographic Assertions</span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/60 text-slate-400">
              <span>Signature Scheme</span>
              <span className="font-mono text-slate-200">ECDSA_P256_SHA256</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60 text-slate-400">
              <span>SLSA Provenance</span>
              <span className="text-emerald-400 font-medium">SLSA v1.0 Attestation</span>
            </div>
            <div className="flex justify-between py-1 text-slate-400">
              <span>Append-Only Log</span>
              <span className="text-emerald-400 font-medium">Chain Verified (RFC 6962)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

