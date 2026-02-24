import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, '../src/scanner/data');
const REPOS_DIR = path.join(__dirname, '../.payload_repos');

const REPOS = [
    { url: "https://github.com/swisskyrepo/PayloadsAllTheThings.git", name: "PayloadsAllTheThings" },
    { url: "https://github.com/ihebski/XSS-Payloads.git", name: "XSS-Payloads-ihebski" },
    { url: "https://github.com/thevillagehacker/Bug-Hunting-Arsenal.git", name: "Bug-Hunting-Arsenal" },
    { url: "https://github.com/MrPr0fessor/Google-Dorks-for-Cross-site-Scripting-XSS.git", name: "Dorks-XSS" },
    { url: "https://github.com/payload-box/xss-payload-list.git", name: "xss-payload-list" },
    { url: "https://github.com/yogsec/XSS-Payloads.git", name: "XSS-Payloads-yogsec" },
    { url: "https://github.com/yogsec/SQL-Injection-Payloads.git", name: "SQL-Injection-Payloads-yogsec" },
    { url: "https://github.com/Ninja-Yubaraj/SQL-Injection-Payloads-List.git", name: "SQL-Injection-Payloads-Ninja" }
];

// Clean directories
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(REPOS_DIR)) fs.mkdirSync(REPOS_DIR, { recursive: true });

function cloneRepos() {
    console.log('[*] Cloning repositories... This may take a moment.');
    for (const repo of REPOS) {
        const repoPath = path.join(REPOS_DIR, repo.name);
        if (!fs.existsSync(repoPath)) {
            console.log(`    -> Cloning ${repo.name}...`);
            try {
                execSync(`git clone --depth 1 ${repo.url} "${repoPath}"`, { stdio: 'ignore' });
            } catch (e) {
                console.error(`    [!] Failed to clone ${repo.name}`);
            }
        } else {
            console.log(`    -> ${repo.name} already exists. Skipping clone.`);
        }
    }
}

function walkDir(dir, callback) {
    fs.readdirSync(dir).forEach(f => {
        const dirPath = path.join(dir, f);
        const isDirectory = fs.statSync(dirPath).isDirectory();
        if (isDirectory) {
            if (f !== '.git' && f !== 'images' && f !== 'assets') {
                walkDir(dirPath, callback);
            }
        } else {
            if (f.endsWith('.txt') || f.endsWith('.md') || f.endsWith('.csv')) {
                callback(path.join(dir, f));
            }
        }
    });
}

function extractPayloads() {
    console.log('[*] Extracting payloads from all files...');

    const xssPayloads = new Set();
    const sqliPayloads = new Set();
    const dorks = new Set();

    // Specific logic for detecting if a line is a payload
    const isXss = (line) => {
        const l = line.toLowerCase();
        // Catch HTML tags, JS execution contexts
        return (l.includes('<script') || l.includes('javascript:') || l.includes('onerror=') || 
                l.includes('onload=') || l.includes('confirm(') || l.includes('alert(') || l.includes('prompt(') ||
                l.includes('eval(') || l.includes('document.cookie'));
    };

    const isSqli = (line) => {
        const l = line.toLowerCase();
        // Catch SQL injection markers
        return (line.includes("'") && (l.includes(' or ') || l.includes(' and '))) ||
               l.includes('union select') || l.includes('waitfor delay') || l.includes('pg_sleep') ||
               l.includes('dbms_pipe') || l.includes('extractvalue') || l.includes('updatexml') ||
               l.includes('/*!') || l.includes('@@version');
    };

    const isDork = (line) => {
        const l = line.toLowerCase();
        return l.startsWith('inurl:') || l.startsWith('intitle:') || l.startsWith('site:') || l.startsWith('ext:');
    };

    // Replace hardcoded alerts/markers with probeToken template
    const normalizePayload = (line) => {
        let n = line;
        n = n.replace(/alert\([^\)]+\)/g, "alert('${probeToken}')");
        n = n.replace(/prompt\([^\)]+\)/g, "prompt('${probeToken}')");
        n = n.replace(/confirm\([^\)]+\)/g, "confirm('${probeToken}')");
        return n;
    };

    for (const repo of REPOS) {
        const repoPath = path.join(REPOS_DIR, repo.name);
        if (!fs.existsSync(repoPath)) continue;

        let filesProcessed = 0;
        walkDir(repoPath, (filePath) => {
            const content = fs.readFileSync(filePath, 'utf-8');
            const lines = content.split('\n');

            for (let line of lines) {
                line = line.trim();
                if (!line) continue;
                if (line.startsWith('#') || line.startsWith('//') || line.startsWith('/*')) continue;
                if (line.length > 500) continue; // Skip massive lines not typical of standard payloads unless it's a huge evasion payload, but 500 is a safe threshold to avoid parsing garbage

                if (isDork(line)) {
                    dorks.add(line);
                } else if (isXss(line)) {
                    // Extract payload from markdown code blocks if necessary, but line-by-line is usually safe
                    xssPayloads.add(normalizePayload(line));
                } else if (isSqli(line)) {
                    sqliPayloads.add(line);
                }
            }
            filesProcessed++;
        });
        console.log(`    -> Processed ${filesProcessed} files in ${repo.name}`);
    }

    // Write to JSON
    console.log('[*] Saving extracted payloads...');
    
    fs.writeFileSync(path.join(DATA_DIR, 'xss-payloads.json'), JSON.stringify(Array.from(xssPayloads), null, 2));
    fs.writeFileSync(path.join(DATA_DIR, 'sqli-payloads.json'), JSON.stringify(Array.from(sqliPayloads), null, 2));
    fs.writeFileSync(path.join(DATA_DIR, 'dorks.json'), JSON.stringify(Array.from(dorks), null, 2));

    console.log(`    -> XSS: ${xssPayloads.size} payloads`);
    console.log(`    -> SQLi: ${sqliPayloads.size} payloads`);
    console.log(`    -> Dorks: ${dorks.size} items`);
}

async function scrapeArticles() {
    console.log('[*] Scraping supplemental articles...');
    
    const xssSet = new Set(JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'xss-payloads.json'), 'utf-8')));
    const sqliSet = new Set(JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'sqli-payloads.json'), 'utf-8')));

    // Simple fetch for dev.to and portswigger (Medium blocked by 403, using some hardcoded fallbacks from memory if needed, but dev.to passes)
    try {
        const res = await fetch('https://dev.to/deoxys/sql-injection-all-concepts-all-payloads-all-in-one-4ch5');
        if (res.ok) {
            const text = await res.text();
            const matches = text.match(/<code>(.*?)<\/code>/g);
            if (matches) {
                for (const match of matches) {
                    const payload = match.replace(/<\/?code>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
                    if (payload.includes('SELECT') || payload.includes('OR 1=1') || payload.includes("'")) {
                        sqliSet.add(payload);
                    }
                }
            }
        }
    } catch (e) {
        console.error('Failed to scrape dev.to article');
    }

    try {
        const res = await fetch('https://portswigger.net/web-security/cross-site-scripting/cheat-sheet');
        if (res.ok) {
            const text = await res.text();
             // Simple regex to grab some of the code blocks or payload strings
            const matches = text.match(/>([^<>]*?alert\(.*?)<\/a>/g);
            if (matches) {
                for (let match of matches) {
                    let payload = match.replace(/<\/?a[^>]*>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#39;/g, "'").replace(/&quot;/g, '"');
                    payload = payload.replace(/alert\([^\)]+\)/g, "alert('${probeToken}')");
                    xssSet.add(payload);
                }
            }
        }
    } catch (e) {
        console.error('Failed to scrape portswigger article');
    }

    fs.writeFileSync(path.join(DATA_DIR, 'xss-payloads.json'), JSON.stringify(Array.from(xssSet), null, 2));
    fs.writeFileSync(path.join(DATA_DIR, 'sqli-payloads.json'), JSON.stringify(Array.from(sqliSet), null, 2));

    console.log(`    -> After articles: XSS: ${xssSet.size}, SQLi: ${sqliSet.size}`);
}

async function main() {
    cloneRepos();
    extractPayloads();
    await scrapeArticles();
    console.log('[*] Integration script complete. Data stored in src/scanner/data/');
}

main().catch(console.error);
