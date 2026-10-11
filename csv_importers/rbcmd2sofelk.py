#!/usr/bin/env python3
from __future__ import annotations
import argparse, sys
from pathlib import Path
from sof_elk_csv_bulk_common import process_csv_import
PREFS=['deletiontime','deletedtime','deletiontimestamp','timestamp','sourcecreated']
HINTS=('rbcmd','recyclebin')
def files(root): return [p for p in (root.rglob('*.csv') if root.is_dir() else [root]) if p.is_file() and p.suffix.lower()=='.csv' and any(h in p.name.lower() for h in HINTS)]
def main():
 p=argparse.ArgumentParser(description='Import RBCmd CSV output directly into Elasticsearch.'); p.add_argument('input'); p.add_argument('--hostname',required=True); p.add_argument('--es',default='http://localhost:9200'); p.add_argument('--user'); p.add_argument('--password'); p.add_argument('--insecure',action='store_true'); p.add_argument('--batch-size',type=int,default=2000); p.add_argument('--workers',type=int,default=2); p.add_argument('--case'); p.add_argument('--local-tz'); p.add_argument('--dry-run',action='store_true'); p.add_argument('--sample-docs',type=int,default=2); a=p.parse_args(); root=Path(a.input).expanduser().resolve(); fs=files(root); 
 if not fs: print(f'ERROR: no RBCmd CSV files found under {root}'); return 2
 try: return process_csv_import(fs,hostname=a.hostname,tool_key='RBCmd',index=f'recyclebin-{a.hostname.lower()}',es=a.es,user=a.user,password=a.password,insecure=a.insecure,batch_size=a.batch_size,workers=a.workers,case=a.case,local_tz=a.local_tz,time_preferences=PREFS,dry_run=a.dry_run,sample_docs=a.sample_docs)
 except Exception as e: print(f'ERROR: {e}'); return 1
if __name__=='__main__': raise SystemExit(main())
