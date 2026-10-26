"""Private inference worker. No website crawling, execution or permission-grant tools here."""
import hmac,io,json,os,hashlib

def create_app():
    import torch
    from fastapi import FastAPI,Header,HTTPException,Request
    from tokenizers import Tokenizer
    from v30_expanded_model import Model,Config,encode_chat
    from vd2_hub import Hub
    # Request is looked up from globals by FastAPI on some releases.
    globals()['Request']=Request
    token=os.environ.get('NEBULA_VD2_WORKER_TOKEN','')
    if len(token)<32:raise RuntimeError('Configure a strong private worker token')
    hub=Hub(os.environ['NEBULA_VD2_REPO'],os.environ['HF_TOKEN']);state=hub.state()
    if not state or not state.get('working'):raise RuntimeError('No trained V-D2 weights exist')
    if not state.get('qualityApproved') and os.environ.get('NEBULA_VD2_ALLOW_EXPERIMENTAL')!='true':raise RuntimeError('Unapproved checkpoint. Complete coding evaluation or explicitly enable owner-only experimental serving.')
    blob=hub.read_entry(hub.repo,hub.revision,state['working']);saved=torch.load(io.BytesIO(blob),map_location='cpu',weights_only=True)
    model=Model(Config(**state['config']['model']));model.load_state_dict(saved['model']);del saved,blob
    device='cuda' if torch.cuda.is_available() else 'cpu';model.to(device).eval();tokenizer=Tokenizer.from_str(hub.read_entry(hub.repo,hub.revision,state['tokenizer']).decode());checkpoint='sha256:'+state['working']['sha256']
    import asyncio
    lock=asyncio.Lock();app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    @app.post('/generate')
    async def generate(request:Request,authorization:str=Header(default='')):
        if not hmac.compare_digest(authorization,'Bearer '+token):raise HTTPException(401,'Unauthorized')
        body=bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body)>120000:raise HTTPException(413,'Request too large')
        try:
            value=json.loads(body);messages=value['messages'];limit=value['maxNewTokens']
            if value['model']!='nebula-v-d2' or len(messages)!=2 or messages[0]['role']!='system' or messages[1]['role']!='user' or type(limit)is not int or not 1<=limit<=2048:raise ValueError()
            ids,_=encode_chat(tokenizer,messages,answer_prefix=True)
        except Exception:raise HTTPException(400,'Invalid generation request')
        if len(ids)>=model.config.context-32:raise HTTPException(413,'Prompt exceeds context; send a smaller code excerpt')
        if lock.locked():raise HTTPException(429,'Worker busy')
        def complete():
            out=[]
            with torch.inference_mode():
                for _ in range(min(limit,model.config.context-len(ids))):
                    x=torch.tensor([ids+out],device=device)
                    logits=model(x)[0,-1].float();logits[[0,1,3,4,5,6,7,8]]=-float('inf');next=int(logits.argmax())
                    if next==2:break
                    out.append(next)
            return tokenizer.decode(out,skip_special_tokens=True)
        async with lock:text=await asyncio.to_thread(complete)
        return dict(model='nebula-v-d2',checkpoint=checkpoint,text=text,experimental=not state.get('qualityApproved',False))
    return app
