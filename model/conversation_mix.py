"""Deterministic 80/20 update scheduling shared by all GPU ranks."""
def conversational(row):
    source=row.get('source',{});curriculum=source.get('curriculum','')
    if curriculum=='v13-language':return False
    return curriculum in ['v5-conversation','v6-conversation','v6-reviewed'] or (source.get('kind')=='public' and source.get('dataset')!='roneneldan/TinyStories') or (source.get('kind')=='teacher' and source.get('trainingAllowed') is True)

def mixed_lane(step):
    # Every five updates: four conversation batches and one mixed batch.
    if step%5!=4:return 'conversation'
    return 'memory' if (step//5)%2==0 else 'mixed'
