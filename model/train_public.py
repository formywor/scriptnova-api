"""Larger from-scratch Nebula training on cached public data, on CPU or CUDA."""
import argparse
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

root=Path(__file__).resolve().parent
runtime=root.parents[3]/'work/nebula-python-deps'
if runtime.joinpath('torch').is_dir(): sys.path.insert(0,str(runtime))
import torch
from nebula import config_for_preset,load,Nebula
from dataflow import prepare,read_jsonl
from train import train
from public_data import download

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download',action='store_true')
    parser.add_argument('--preset',choices=['cpu-medium','cpu-large','gpu'],default='cpu-large')
    parser.add_argument('--stage',choices=['language','chat'],default='language')
    parser.add_argument('--steps',type=int,default=2000)
    parser.add_argument('--continuous',action='store_true',help='Keep training until interrupted; disables validation early stopping')
    parser.add_argument('--batch',type=int,default=2)
    parser.add_argument('--threads',type=int,default=min(4,os.cpu_count() or 1))
    parser.add_argument('--device',choices=['auto','cpu','cuda'],default='auto')
    parser.add_argument('--save-every',type=int,default=200)
    parser.add_argument('--max-validation',type=int,default=128)
    parser.add_argument('--patience',type=int,default=5)
    parser.add_argument('--lr',type=float,default=.0001,help='Learning rate; reduce this if numerical errors occur')
    parser.add_argument('--resume',help='Resume weights from a compatible checkpoint')
    parser.add_argument('--prepared-data',help='Use an existing prepared JSONL dataset without rewriting its bytes')
    args=parser.parse_args()
    if args.max_validation<1: parser.error('--max-validation must be positive')
    if args.prepared_data:
        if args.download: parser.error('--download and --prepared-data cannot be combined')
        prepared=Path(args.prepared_data)
        if not prepared.is_file(): parser.error('Prepared dataset was not found')
        count=len(read_jsonl(prepared))
    else:
        data=root/'data/public-conversations.jsonl'
        if args.download: download(root/'data')
        if not data.exists(): parser.error('Download data first: python model/public_data.py')
        prepared=root/'data/public-approved.jsonl'
        count=prepare([data,root/'seed.jsonl'],prepared)
    config=config_for_preset(args.preset)
    output=root/f'checkpoints/nebula-{args.preset}-{args.stage}.pt'
    resume=Path(args.resume) if args.resume else output if output.exists() else None
    if args.stage=='chat' and resume is None:
        language=root/f'checkpoints/nebula-{args.preset}-language.best.pt'
        if not language.exists(): parser.error('Run the language stage first, or explicitly provide --resume')
        resume=language
    if resume:
        previous,_=load(resume)
        if previous.config!=config: parser.error('Checkpoint size does not match preset; choose a new output preset or compatible checkpoint')
        parameters=sum(p.numel() for p in previous.parameters()); del previous
    else:
        probe=Nebula(config); parameters=sum(p.numel() for p in probe.parameters()); del probe
    print(json.dumps({'parameters':parameters,'contextBytes':config.context,'originalConversations':count,'stage':args.stage,'requestedDevice':args.device,'cudaAvailable':torch.cuda.is_available(),'resumeWeights':str(resume) if resume else None,'note':'Experimental from-scratch model; this run does not update the live website.'}),flush=True)
    train(SimpleNamespace(data=prepared,output=output,snapshot=None,resume=resume,preset=args.preset,steps=args.steps,batch=args.batch,threads=args.threads,seed=42,lr=args.lr,continuous=args.continuous,save_every=args.save_every,patience=0 if args.continuous else args.patience,device=args.device,amp=True,objective='assistant' if args.stage=='chat' else 'language',grouped_split=True,bucketed=True,max_validation=args.max_validation))

if __name__=='__main__': main()
