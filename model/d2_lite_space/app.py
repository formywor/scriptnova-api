print('D2_LITE_BOOT',flush=True)
import spaces
print('D2_LITE_SPACES_IMPORTED',flush=True)
import gc,json,os,time
from pathlib import Path
import torch
print('D2_LITE_TORCH_IMPORTED',flush=True)
import gradio as gr
from fastapi import FastAPI,Request
from fastapi.responses import JSONResponse
from tokenizers import Tokenizer
from checkpoint import authorized,download,validate_payload
from v30_expanded_model import Model,Config,encode_chat

ROOT=Path(__file__).parent
MANIFEST=json.loads((ROOT/'manifest.json').read_text())
SECRET=os.environ.get('NEBULA_D2_LITE_WORKER_KEY','')
CACHE=Path('/tmp/nebula-d2-lite-artifacts')
torch.set_num_threads(2)
print('D2_LITE_DOWNLOADING_WEIGHTS',flush=True)
weights=download(MANIFEST['working'],MANIFEST,CACHE)
print('D2_LITE_LOADING_WEIGHTS',flush=True)
saved=torch.load(weights,map_location='cpu',weights_only=True,mmap=True)
with torch.device('meta'):model=Model(Config(**MANIFEST['model']))
model.load_state_dict(saved['model'],strict=True,assign=True)
model.output.weight=model.token.weight
model.mask=torch.empty(0,dtype=torch.bool)
del saved;gc.collect()
model.to(device='cuda',dtype=torch.float16).eval()
print('D2_LITE_MODEL_LOADED',flush=True)
tokenizer=Tokenizer.from_file(str(download(MANIFEST['tokenizer'],MANIFEST,CACHE)))
CHECKPOINT='sha256:'+MANIFEST['working']['sha256']

@spaces.GPU(duration=60)
def complete(payload):
    messages,limit=validate_payload(payload)
    ids,_=encode_chat(tokenizer,messages,answer_prefix=True)
    if len(ids)>=model.config.context-32:raise gr.Error('D2_CONTEXT_TOO_LONG')
    out=[];started=time.monotonic()
    with torch.inference_mode():
        for _ in range(min(limit,model.config.context-len(ids))):
            if time.monotonic()-started>50:break
            x=torch.tensor([ids+out],device='cuda')
            logits=model(x)[0,-1].float();logits[[0,1,3,4,5,6,7,8]]=-float('inf');token=int(logits.argmax())
            if token==2:break
            out.append(token)
    return {'model':'nebula-v-d2','checkpoint':CHECKPOINT,'text':tokenizer.decode(out,skip_special_tokens=True),'experimental':True}

def generate(payload):
    validate_payload(payload)
    return complete(payload)

with gr.Blocks(analytics_enabled=False) as demo:
    gr.Markdown('Nebula D2 Lite — managed experimental checkpoint service')
    data=gr.JSON(visible=False);result=gr.JSON(visible=False)
    button=gr.Button('Managed service',visible=False)
    button.click(generate,inputs=[data],outputs=[result],api_name='generate')
demo.queue(max_size=4,default_concurrency_limit=1)
app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
@app.middleware('http')
async def protect(request:Request,call_next):
    if request.url.path.startswith('/worker'):
        if len(SECRET)<32:return JSONResponse({'code':'WORKER_NOT_CONFIGURED'},status_code=503)
        if not authorized(request.headers.get('x-nebula-worker-key',''),SECRET):return JSONResponse({'code':'UNAUTHORIZED'},status_code=401)
        if int(request.headers.get('content-length','0'))>120000:return JSONResponse({'code':'TOO_LARGE'},status_code=413)
    return await call_next(request)
@app.get('/')
@app.get('/healthz')
def health():return {'model':'nebula-v-d2','checkpoint':CHECKPOINT,'updates':MANIFEST['updates'],'experimental':True,'weightsLoaded':True,'ready':len(SECRET)>=32}
app=gr.mount_gradio_app(app,demo,path='/worker',ssr_mode=False,show_error=False)
if __name__=='__main__':
    import uvicorn
    port=int(os.environ.get('GRADIO_SERVER_PORT','7860'))
    print('D2_LITE_HTTP_PORT',port,flush=True)
    uvicorn.run(app,host='0.0.0.0',port=port,access_log=False)
