const fs = require('fs');
const f = 'C:/Users/n/Desktop/New folder (4)/pentest/src/app/(platform)/vulnerabilities/[id]/page.tsx';
const lines = fs.readFileSync(f, 'utf8').split('\r\n');

// Find the SqliExploitPanel function and the import section to add new icons
// Add new type imports
for (let i = 0; i < lines.length; i++) {
  if (lines[i].includes("import type { SqliExploitResult }")) {
    lines[i] = "import type { SqliExploitResult, PasswordHash, FileReadResult, OsCommandResult, TestedTechnique } from '@/types';";
    console.log('OK: Updated imports at line ' + i);
    break;
  }
}

// Add new icons to the lucide import
for (let i = 0; i < lines.length; i++) {
  if (lines[i].includes('Terminal, Zap, Hash, Eye,')) {
    lines[i] = "    Terminal, Zap, Hash, Eye, ShieldAlert, FileKey, Cpu, Clock, Activity, KeyRound,";
    console.log('OK: Updated icons at line ' + i);
    break;
  }
}

// Find the end of SqliExploitPanel (the closing of the stats row "    </div>") just before DB tree
// We need to insert new sections after the stats row and before the DB tree

// Find "            {/* ── Database Tree View ── */}"
let dbTreeIdx = -1;
for (let i = 0; i < lines.length; i++) {
  if (lines[i].includes('Database Tree View')) {
    dbTreeIdx = i;
    break;
  }
}

if (dbTreeIdx < 0) {
  console.log('FAIL: Database Tree View not found');
  process.exit(1);
}

const newSections = [
  '',
  '            {/* ── Privilege & Auth Section ── */}',
  '            <div className="relative overflow-hidden rounded-2xl border border-amber-500/15 bg-gradient-to-br from-amber-950/20 via-surface-900/80 to-surface-900/80 backdrop-blur-xl p-5">',
  '                <div className="flex items-center gap-2 mb-4">',
  '                    <ShieldAlert className="w-4 h-4 text-amber-400" />',
  '                    <h3 className="text-sm font-semibold text-gray-200">Privilege & Authentication</h3>',
  '                    {data.isDBA && <span className="ml-2 px-2 py-0.5 rounded-full bg-red-500/15 border border-red-500/25 text-[10px] font-bold text-red-400 uppercase tracking-wider animate-pulse">⚡ DBA / ADMIN</span>}',
  '                </div>',
  '                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">',
  '                    <InfoChip icon={<ShieldAlert className="w-3.5 h-3.5" />} label="DBA" value={data.isDBA ? "YES ⚡" : "No"} color={data.isDBA ? "red" : "green"} />',
  '                    <InfoChip icon={<Cpu className="w-3.5 h-3.5" />} label="Server OS" value={data.serverOS || "—"} color="blue" />',
  '                    <InfoChip icon={<Activity className="w-3.5 h-3.5" />} label="Architecture" value={data.serverArch || "—"} color="cyan" />',
  '                    <InfoChip icon={<User className="w-3.5 h-3.5" />} label="Users Found" value={`${data.allUsers?.length || 0}`} color="violet" />',
  '                </div>',
  '                {data.privileges?.length > 0 && (',
  '                    <div className="mb-3">',
  '                        <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Privileges</p>',
  '                        <div className="flex flex-wrap gap-1.5">',
  '                            {data.privileges.map(p => (',
  '                                <span key={p} className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${/FILE|SUPER|PROCESS|SHUTDOWN|GRANT|CREATE USER|RELOAD/i.test(p) ? "bg-red-500/10 text-red-300 border-red-500/20" : "bg-amber-500/5 text-amber-300 border-amber-500/15"}`}>{p}</span>',
  '                            ))}',
  '                        </div>',
  '                    </div>',
  '                )}',
  '                {data.roles?.length > 0 && (',
  '                    <div>',
  '                        <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Roles</p>',
  '                        <div className="flex flex-wrap gap-1.5">',
  '                            {data.roles.map(r => (',
  '                                <span key={r} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-violet-500/10 text-violet-300 border border-violet-500/20">{r}</span>',
  '                            ))}',
  '                        </div>',
  '                    </div>',
  '                )}',
  '            </div>',
  '',
  '            {/* ── Password Hashes Table ── */}',
  '            {data.passwordHashes?.length > 0 && (',
  '                <div className="rounded-2xl border border-red-500/15 bg-gradient-to-br from-red-950/15 via-surface-900/80 to-surface-900/80 backdrop-blur-xl overflow-hidden">',
  '                    <div className="px-5 py-3.5 border-b border-white/[0.04] flex items-center gap-2">',
  '                        <KeyRound className="w-4 h-4 text-red-400" />',
  '                        <h3 className="text-sm font-semibold text-gray-200">Password Hashes</h3>',
  '                        <span className="ml-auto text-[10px] text-red-400 font-mono">{data.passwordHashes.length} hashes extracted</span>',
  '                    </div>',
  '                    <div className="overflow-x-auto">',
  '                        <table className="w-full text-xs font-mono">',
  '                            <thead><tr className="bg-red-500/5 border-b border-red-500/10">',
  '                                <th className="px-4 py-2 text-left text-red-400/70 font-semibold text-[10px] uppercase">Username</th>',
  '                                <th className="px-4 py-2 text-left text-red-400/70 font-semibold text-[10px] uppercase">Hash</th>',
  '                                <th className="px-4 py-2 text-left text-red-400/70 font-semibold text-[10px] uppercase">Type</th>',
  '                            </tr></thead>',
  '                            <tbody>',
  '                                {data.passwordHashes.map((h: PasswordHash, i: number) => (',
  '                                    <tr key={i} className={`border-b border-white/[0.02] ${i % 2 === 0 ? "bg-surface-900/50" : "bg-surface-800/30"} hover:bg-red-500/5 transition-colors`}>',
  '                                        <td className="px-4 py-2 text-amber-300 font-semibold">{h.username}</td>',
  '                                        <td className="px-4 py-2 text-gray-400 max-w-[300px] truncate" title={h.hash}>{h.hash}</td>',
  '                                        <td className="px-4 py-2"><span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-red-500/10 text-red-400 border border-red-500/20 uppercase">{h.hashType}</span></td>',
  '                                    </tr>',
  '                                ))}',
  '                            </tbody>',
  '                        </table>',
  '                    </div>',
  '                </div>',
  '            )}',
  '',
  '            {/* ── File System Access ── */}',
  '            {(data.fileReadResults?.length > 0 || data.fileWriteCapable) && (',
  '                <div className="rounded-2xl border border-blue-500/15 bg-gradient-to-br from-blue-950/15 via-surface-900/80 to-surface-900/80 backdrop-blur-xl p-5">',
  '                    <div className="flex items-center gap-2 mb-4">',
  '                        <FileKey className="w-4 h-4 text-blue-400" />',
  '                        <h3 className="text-sm font-semibold text-gray-200">File System Access</h3>',
  '                        {data.fileWriteCapable && <span className="ml-2 px-2 py-0.5 rounded-full bg-red-500/15 border border-red-500/25 text-[10px] font-bold text-red-400 uppercase">⚠ WRITE CAPABLE</span>}',
  '                    </div>',
  '                    {data.fileReadResults?.map((fr: FileReadResult, i: number) => (',
  '                        <div key={i} className="mb-3">',
  '                            <div className="flex items-center gap-2 mb-1">',
  '                                <span className="text-xs font-mono text-blue-300">{fr.path}</span>',
  '                                <span className="text-[9px] text-gray-500">{fr.size} bytes</span>',
  '                                {fr.success && <span className="text-[9px] text-green-400">✓ READ</span>}',
  '                            </div>',
  '                            <div className="code-block text-xs max-h-32 overflow-y-auto">{fr.content}</div>',
  '                        </div>',
  '                    ))}',
  '                </div>',
  '            )}',
  '',
  '            {/* ── OS Shell Section ── */}',
  '            {data.osShellAvailable && (',
  '                <div className="rounded-2xl border border-red-600/20 bg-gradient-to-br from-red-950/20 via-surface-900/80 to-surface-900/80 backdrop-blur-xl overflow-hidden">',
  '                    <div className="px-5 py-3.5 border-b border-white/[0.04] flex items-center gap-2">',
  '                        <Terminal className="w-4 h-4 text-red-400" />',
  '                        <h3 className="text-sm font-semibold text-red-300">OS Shell Access</h3>',
  '                        <span className="ml-auto px-2.5 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-[10px] font-bold text-red-400 uppercase animate-pulse">ACTIVE</span>',
  '                    </div>',
  '                    <div className="p-4 font-mono text-xs space-y-1">',
  '                        {data.osCommandResults?.map((cmd: OsCommandResult, i: number) => (',
  '                            <div key={i} className="rounded-lg bg-surface-950/80 p-3 border border-white/[0.03]">',
  '                                <div className="flex items-center gap-2 mb-1.5">',
  '                                    <span className="text-green-400">$</span>',
  '                                    <span className="text-cyan-300">{cmd.command}</span>',
  '                                    {cmd.success && <Zap className="w-3 h-3 text-green-400 ml-auto" />}',
  '                                </div>',
  '                                <pre className="text-gray-400 whitespace-pre-wrap text-[11px] leading-relaxed">{cmd.output}</pre>',
  '                            </div>',
  '                        ))}',
  '                    </div>',
  '                </div>',
  '            )}',
  '',
  '            {/* ── WAF Detection Card ── */}',
  '            {(data.wafDetected || data.wafFingerprints?.length > 0) && (',
  '                <div className="rounded-2xl border border-orange-500/15 bg-gradient-to-br from-orange-950/15 via-surface-900/80 to-surface-900/80 backdrop-blur-xl p-5">',
  '                    <div className="flex items-center gap-2 mb-3">',
  '                        <Shield className="w-4 h-4 text-orange-400" />',
  '                        <h3 className="text-sm font-semibold text-gray-200">WAF Detection</h3>',
  '                        {data.wafDetected && <span className="ml-2 px-2.5 py-0.5 rounded-full bg-orange-500/10 border border-orange-500/20 text-[10px] font-bold text-orange-400 uppercase">{data.wafDetected}</span>}',
  '                    </div>',
  '                    {data.wafBypassEncoder && <p className="text-xs text-green-300 mb-2">✓ Bypass encoder: <span className="font-mono text-green-400">{data.wafBypassEncoder}</span></p>}',
  '                    {data.wafFingerprints?.length > 0 && (',
  '                        <div className="flex flex-wrap gap-1.5">',
  '                            {data.wafFingerprints.map(w => (',
  '                                <span key={w} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-orange-500/5 text-orange-300 border border-orange-500/15">{w}</span>',
  '                            ))}',
  '                        </div>',
  '                    )}',
  '                </div>',
  '            )}',
  '',
  '            {/* ── Techniques Breakdown ── */}',
  '            {data.allTestedTechniques?.length > 0 && (',
  '                <div className="rounded-2xl border border-cyan-500/15 bg-gradient-to-br from-cyan-950/15 via-surface-900/80 to-surface-900/80 backdrop-blur-xl p-5">',
  '                    <div className="flex items-center gap-2 mb-4">',
  '                        <Activity className="w-4 h-4 text-cyan-400" />',
  '                        <h3 className="text-sm font-semibold text-gray-200">Injection Techniques</h3>',
  '                    </div>',
  '                    <div className="space-y-2">',
  '                        {data.allTestedTechniques.map((t: TestedTechnique) => (',
  '                            <div key={t.technique} className={`flex items-center gap-3 px-4 py-2.5 rounded-xl border transition-all ${t.success ? "bg-green-500/5 border-green-500/15" : t.tested ? "bg-red-500/5 border-red-500/10 opacity-60" : "bg-surface-800/50 border-white/[0.03] opacity-40"}`}>',
  '                                <span className="flex-shrink-0 w-5 text-center">{t.success ? <Zap className="w-4 h-4 text-green-400 inline" /> : t.tested ? <span className="text-red-400 text-sm">✗</span> : <span className="text-gray-600 text-sm">—</span>}</span>',
  '                                <span className={`text-sm font-mono font-semibold ${t.success ? "text-green-300" : "text-gray-500"}`}>{t.technique}</span>',
  '                                {t.note && <span className="text-[10px] text-gray-500 ml-auto">{t.note}</span>}',
  '                            </div>',
  '                        ))}',
  '                    </div>',
  '                    {data.tamperScripts?.length > 0 && (',
  '                        <div className="mt-4 pt-3 border-t border-white/[0.04]">',
  '                            <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Tamper Scripts / Encoders</p>',
  '                            <div className="flex flex-wrap gap-1.5">',
  '                                {data.tamperScripts.map(t => (',
  '                                    <span key={t} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/5 text-cyan-300 border border-cyan-500/15">{t}</span>',
  '                                ))}',
  '                            </div>',
  '                        </div>',
  '                    )}',
  '                </div>',
  '            )}',
  '',
  '            {/* ── Performance Stats ── */}',
  '            {data.startTime && data.endTime && (',
  '                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">',
  '                    <StatCard label="Duration" value={Math.round((data.endTime - data.startTime) / 1000)} icon={<Clock className="w-4 h-4" />} color="violet" />',
  '                    <StatCard label="Requests" value={data.totalRequests || 0} icon={<Activity className="w-4 h-4" />} color="cyan" />',
  '                    <StatCard label="Data (bytes)" value={data.totalDataExtracted || 0} icon={<Database className="w-4 h-4" />} color="green" />',
  '                    <StatCard label="Avg Response" value={data.avgResponseTime || 0} icon={<Zap className="w-4 h-4" />} color="amber" />',
  '                    <StatCard label="Hashes" value={data.passwordHashes?.length || 0} icon={<KeyRound className="w-4 h-4" />} color="violet" />',
  '                </div>',
  '            )}',
  '',
];

lines.splice(dbTreeIdx, 0, ...newSections);
console.log('OK: New UI sections inserted before Database Tree View at line ' + dbTreeIdx);

fs.writeFileSync(f, lines.join('\r\n'));
console.log('DONE: UI enhanced');
