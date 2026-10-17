"""Measure local CPU training throughput rather than assuming more threads help."""
import argparse
import json
import os
from pathlib import Path
import sys
import time

root=Path(__file__).resolve().parent
runtime=root.parents[3]/'work/nebula-python-deps'
if runtime.joinpath('torch').is_dir(): sys.path.insert(0,str(runtime))
import torch
from nebula import Nebula,config_for_preset

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--length',type=int,default=512)
    parser.add_argument('--iterations',type=int,default=3)
    args=parser.parse_args()
    if not 1<=args.length<=1024 or not 1<=args.iterations<=10: parser.error('Use length 1-1024 and iterations 1-10')
    results=[]
    for preset in ['cpu','cpu-medium','cpu-large']:
        for threads in [n for n in [1,2,4] if n<=os.cpu_count()]:
            torch.set_num_threads(threads); torch.manual_seed(42)
            model=Nebula(config_for_preset(preset)); optimizer=torch.optim.AdamW(model.parameters(),lr=.0003)
            x=torch.randint(0,256,(1,args.length)); y=torch.randint(0,256,(1,args.length))
            def step():
                optimizer.zero_grad(set_to_none=True)
                value=torch.nn.functional.cross_entropy(model(x).reshape(-1,262),y.reshape(-1))
                value.backward(); optimizer.step()
            step(); started=time.perf_counter()
            for _ in range(args.iterations): step()
            elapsed=time.perf_counter()-started
            record={'preset':preset,'parameters':sum(p.numel() for p in model.parameters()),'threads':threads,'batch':1,'sequenceBytes':args.length,'secondsPerStep':round(elapsed/args.iterations,4),'tokensPerSecond':round(args.length*args.iterations/elapsed)}
            results.append(record); print(json.dumps(record),flush=True)
            del optimizer,model
    return results

if __name__=='__main__': main()
