"""V15 uses the tested V14 optimizer/DDP engine with full-conversation windows."""
import v14_train as engine
from v15_data import pools,pick

def main(argv=None):
    original=(engine.pools,engine.pick,engine.FORMAT)
    try:
        engine.pools=pools;engine.pick=pick;engine.FORMAT='nebula-v15-full-chat-train-1'
        return engine.main(argv,allow_world_change=True)
    finally:engine.pools,engine.pick,engine.FORMAT=original

if __name__=='__main__':main()
