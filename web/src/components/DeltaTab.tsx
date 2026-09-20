import { Box, CheckCircle } from 'lucide-react';

export function DeltaTab() {
  return (
    <div className="space-y-6">
      <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 space-y-3">
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <Box className="w-5 h-5 text-indigo-400" />
          <span>Cross-Layer Historical Build Delta Comparator</span>
        </h2>
        <p className="text-xs text-slate-400 max-w-2xl">
          Deep differential analysis comparing Build 1 and Build 2 across compiler runtimes, commands,
          filesystem mutations, network sockets, and output artifact Merkle roots.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="font-mono text-sm font-bold text-sky-400">Run 1: build-001</div>
            <span className="text-[11px] text-slate-400">2026-09-20 10:00:00Z</span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/40 text-slate-400">
              <span>Host Architecture</span>
              <span className="font-mono text-slate-200">linux / amd64</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40 text-slate-400">
              <span>Compiler Toolchain</span>
              <span className="font-mono text-slate-200">go1.23.6</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40 text-slate-400">
              <span>Artifact SHA-256</span>
              <span className="font-mono text-slate-200">bff2ef7b7dbc...</span>
            </div>
            <div className="flex justify-between py-1 text-slate-400">
              <span>Filesystem Delta</span>
              <span className="text-slate-200">1 created artifact</span>
            </div>
          </div>
        </div>

        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="font-mono text-sm font-bold text-indigo-400">Run 2: build-002</div>
            <span className="text-[11px] text-slate-400">2026-09-20 10:05:00Z</span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/40 text-slate-400">
              <span>Host Architecture</span>
              <span className="font-mono text-slate-200">linux / amd64</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40 text-slate-400">
              <span>Compiler Toolchain</span>
              <span className="font-mono text-slate-200">go1.23.6</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40 text-slate-400">
              <span>Artifact SHA-256</span>
              <span className="font-mono text-slate-200">bff2ef7b7dbc...</span>
            </div>
            <div className="flex justify-between py-1 text-slate-400">
              <span>Filesystem Delta</span>
              <span className="text-slate-200">1 created artifact</span>
            </div>
          </div>
        </div>
      </div>

      <div className="p-5 rounded-xl border border-emerald-500/30 bg-emerald-950/20 flex items-center space-x-3">
        <CheckCircle className="w-5 h-5 text-emerald-400 flex-shrink-0" />
        <div className="text-xs text-emerald-300 leading-relaxed">
          <span className="font-bold text-emerald-200">Bitwise Reproducibility Confirmed: </span>
          Both builds generated bit-for-bit identical binaries across independent invocations.
        </div>
      </div>
    </div>
  );
}

