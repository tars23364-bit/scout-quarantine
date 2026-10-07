// scout deep review, P3 (R3): canarycheck's in-container memory dump. Run inside a box or the proxy
// with `docker exec -i <name> node - < memscan.js`: streams every readable, non-file-backed memory
// range of every OTHER process in the container to stdout, for the HOST to scan by value (the bytes
// are never stored). Same-uid /proc/<pid>/mem reads; stderr = {procs, total bytes, errors}.
const fs=require('fs');
const self=String(process.pid);
let total=0, zero=0, procs=0, errs=[];
const ZERO=Buffer.alloc(1048576);
// blocking writes: a pipe that is full must not drop or reorder chunks
const writeSync=(b)=>{ let o=0; while(o<b.length){ try { o+=fs.writeSync(1,b,o); } catch(e){ if(e.code!=='EAGAIN') throw e; } } };
for (const pid of fs.readdirSync('/proc').filter(d=>/^\d+$/.test(d) && d!==self)) {
  let maps; try { maps=fs.readFileSync(`/proc/${pid}/maps`,'utf8'); } catch(e){ errs.push(pid+':maps:'+e.code); continue; }
  let fd; try { fd=fs.openSync(`/proc/${pid}/mem`,'r'); } catch(e){ errs.push(pid+':mem:'+e.code); continue; }
  procs++;
  for (const line of maps.split('\n')) {
    const m=/^([0-9a-f]+)-([0-9a-f]+) (r)/.exec(line); if(!m) continue;
    if (/\.so|\/node$|\/claude|\/codex/.test(line) && !/\[heap\]/.test(line) && / [0-9a-f]+ [0-9a-f]+:[0-9a-f]+ [1-9]/.test(line)) continue; // skip file-backed code
    const a=BigInt('0x'+m[1]), b=BigInt('0x'+m[2]);
    for (let off=a; off<b; off+=1048576n) {
      const n=Number((b-off)>1048576n?1048576n:(b-off)); const buf=Buffer.alloc(n);
      try {
        const r=fs.readSync(fd,buf,0,n,off);
        if (r>0) {
          const chunk=buf.subarray(0,r);
          // all-zero chunks (untouched reservations: the Bun/JSC heap reserves gigabytes) hold no value
          if (chunk.equals(ZERO.subarray(0,r))) { zero+=r; continue; }
          writeSync(chunk); total+=r;
        }
      } catch(e) {}
    }
  }
  fs.closeSync(fd);
}
process.stderr.write(JSON.stringify({procs,total,zero_bytes_skipped:zero,errs:errs.slice(0,5)})+'\n');
