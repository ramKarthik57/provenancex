import { HardDrive, CheckCircle2 } from 'lucide-react';

export function BundleTab() {
  return (
    <div className="space-y-6">
      <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 space-y-3">
        <h2 className="text-lg font-bold text-white flex items-center space-x-2">
          <HardDrive className="w-5 h-5 text-emerald-400" />
          <span>Air-Gapped Portable Evidence Bundle (.tar.gz)</span>
        </h2>
        <p className="text-xs text-slate-400 max-w-2xl">
          Seals software binaries, in-toto SLSA attestations, CycloneDX/SPDX SBOMs, digital signatures,
          and RFC 6962 tamper-evident hash chains into a normalized, self-verifying archive.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3">
          <div className="text-sm font-bold text-white">Bundle Structure & Files</div>
          <div className="space-y-2 font-mono text-xs">
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80 flex items-center justify-between">
              <span className="text-sky-400">bundle-manifest.json</span>
              <span className="text-[11px] text-slate-500">Cryptographic Index</span>
            </div>
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80 flex items-center justify-between">
              <span className="text-indigo-400">artifact/sample-app</span>
              <span className="text-[11px] text-slate-500">Binary Output</span>
            </div>
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80 flex items-center justify-between">
              <span className="text-emerald-400">provenance/provenance.json</span>
              <span className="text-[11px] text-slate-500">SLSA v1.0 Statement</span>
            </div>
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80 flex items-center justify-between">
              <span className="text-amber-400">signature/signature.sig</span>
              <span className="text-[11px] text-slate-500">ECDSA Assertion</span>
            </div>
          </div>
        </div>

        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3">
          <div className="text-sm font-bold text-white">Offline Verification Checks</div>
          <div className="space-y-2 text-xs">
            <div className="flex items-center space-x-2 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
              <span>Archive structure & internal checksums verified</span>
            </div>
            <div className="flex items-center space-x-2 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
              <span>Artifact SHA-256 matches provenance subject claim</span>
            </div>
            <div className="flex items-center space-x-2 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
              <span>Digital signature cryptographically valid against public key</span>
            </div>
            <div className="flex items-center space-x-2 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
              <span>Append-only hash chain unbroken (no retroactive tamper)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

