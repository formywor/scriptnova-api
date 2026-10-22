"""Original context curriculum with explicit split axes; no provider or user data."""
import hashlib
import itertools
import json
import random
from functools import lru_cache
import torch
from nebula import BOS, EOS, encode
from rules import with_owner_rules
from v13_windows import windows

VERSION = 'nebula-v17-lab-1'
NAMES = ['Ada','Ben','Cleo','Dara','Eli','Faye','Gus','Hana','Ivan','Jade','Kira','Leo','Mina','Noel','Omar','Pia','Ravi','Sara','Theo','Uma','Vera','Will','Xena','Yuri']
COLORS = ['red','blue','green','gold','pink','white','black','gray','yellow','orange','violet','teal']
PLACES = ['attic','porch','garden','kitchen','office','hall','garage','shed','library','studio','locker','cellar']
KEYS = ['name','color','location']
TRAIN_ORDERS = list(itertools.permutations(KEYS))[:-1]
HELD_ORDER = list(itertools.permutations(KEYS))[-1]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def pair_split(name, color):
    return int(digest([name, color])[:8], 16) % 7


def record(rng, split='train', axis=None):
    while True:
        name, color = rng.choice(NAMES), rng.choice(COLORS)
        wanted = 0 if axis == 'new_combinations' else 1 if split == 'validation' else None
        if (wanted is not None and pair_split(name, color) == wanted) or (wanted is None and pair_split(name, color) >= 2): break
    facts = {'name': name, 'color': color, 'location': rng.choice(PLACES)}
    if axis == 'new_values':
        # Never sampled as training values. Plain and nonce spellings test copying.
        facts = {'name': rng.choice(['Zevrin','Melora','Qexal','Tuvin']),
                 'color': rng.choice(['bronze','silver','maroon','lavender']),
                 'location': rng.choice(['balcony','orchard','workshop','pantry'])}
    order = HELD_ORDER if axis == 'field_order' else rng.choice(TRAIN_ORDERS)
    text = ' '.join(key.title() + ': ' + facts[key] + '.' for key in order)
    query = rng.choice(KEYS)
    form = rng.randrange(3)
    def question(key):
        if axis == 'new_wording': return f'Extract the {key} value. Return nothing else.'
        return [f'Give only the {key}.', f'What is the {key}? Reply with just the value.',
                f'Return the {key} only.'][form]
    messages = [{'role':'user','content':text + ' ' + question(query)},
                {'role':'assistant','content':facts[query]}]
    followup = None
    if axis in ['multi_turn', 'updated_facts'] or (axis is None and rng.random() < .4):
        next_key = rng.choice([k for k in KEYS if k != query])
        if axis == 'updated_facts' or (axis is None and rng.random() < .4):
            # Update location, leaving name/color combinations reserved as designed.
            next_key = 'location'; revised = rng.choice([p for p in PLACES if p != facts[next_key]])
            prompt = f'Correction: location is {revised}. ' + question(next_key)
            answer = revised
        else:
            prompt = question(next_key); answer = facts[next_key]
        followup = {'prompt':prompt, 'expected':answer}
        if axis is None:
            messages += [{'role':'user','content':prompt}, {'role':'assistant','content':answer}]
    return {'messages':messages, 'pair':[name,color], 'order':list(order),
            'id':digest(messages), **({'followup':followup} if followup else {})}


def curriculum(count=4000, seed=17017, cases_per_axis=12):
    if not 100 <= count <= 50000 or not 2 <= cases_per_axis <= 100: raise ValueError('Invalid curriculum size')
    rng = random.Random(seed); train = []; seen = set()
    while len(train) < count:
        row = record(rng)
        if row['id'] not in seen: train.append(row); seen.add(row['id'])
    valid = []; seen_valid = set()
    while len(valid) < min(256, count // 4):
        row = record(rng, split='validation')
        if row['id'] not in seen_valid: valid.append(row); seen_valid.add(row['id'])
    tests = []
    for axis in ['new_combinations','new_values','new_wording','field_order','multi_turn','updated_facts']:
        unique = set()
        while len(unique) < cases_per_axis:
            row = record(rng, axis=axis)
            if row['id'] in seen or row['id'] in seen_valid or row['id'] in unique: continue
            unique.add(row['id']); tests.append({**row, 'axis':axis})
    # Reserve the entire benchmark opening, including any follow-up variant.
    prompts = {tuple(m['content'] for m in r['messages'] if m['role']=='user') for r in tests}
    train = [r for r in train if tuple(m['content'] for m in r['messages'] if m['role']=='user') not in prompts
             and r['messages'][0]['content'] not in {t['messages'][0]['content'] for t in tests}]
    return {'training':train, 'validation':valid, 'tests':tests,
            'notice':'Held-out means excluded from V17 training. Public history may contain common words/values; this is not a claim of lifetime novelty.'}


def normalized_content(row):
    return ' '.join(' '.join(m['content'].casefold().split()) for m in row['messages'])


def public_pools(language, language_valid, chats, chats_valid, limit, tests, seed=17017):
    """Reuse whole licensed public records; split by source identity and opening."""
    blocks = {normalized_content(r) for r in tests}
    blocks.update(' '.join(r['messages'][0]['content'].casefold().split()) for r in tests)
    def eligible(row, kind):
        src = row.get('source', {})
        if src.get('kind') != 'public' or not src.get('license') or not src.get('recordId'): return False
        if src.get('curriculum') != ('v13-language' if kind=='language' else 'v13-conversation'): return False
        text = normalized_content(row)
        return not any(b in text for b in blocks)
    result = {}
    def balanced(rows, maximum, kind):
        groups={}
        for row in rows:
            src=row['source'];key=src.get('dataset','unknown') if kind=='language' else str(src.get('component') or src.get('dataset','unknown'))
            groups.setdefault(key,[]).append(row)
        rng=random.Random(seed)
        for values in groups.values():rng.shuffle(values)
        chosen=[]
        while len(chosen)<min(maximum,len(rows)):
            for key in sorted(groups):
                if groups[key]:chosen.append(groups[key].pop())
                if len(chosen)>=maximum:break
        return chosen
    for kind, training, validation in [('language',language,language_valid),('public',chats,chats_valid)]:
        # All held-out identities/openings are blocked, even beyond the sampled validation subset.
        valid_rows = [r for r in validation if eligible(r, 'language' if kind=='language' else 'chat')]
        identity = lambda r: (r['source'].get('dataset'), r['source'].get('recordId'))
        ids = {identity(r) for r in valid_rows}
        content = {normalized_content(r) for r in valid_rows}
        openings = {' '.join(r['messages'][0]['content'].casefold().split()) for r in valid_rows} if kind=='public' else set()
        seen = set(); selected = []
        for r in training:
            if not eligible(r, 'language' if kind=='language' else 'chat'): continue
            key = normalized_content(r)
            if identity(r) in ids or key in content or key in seen: continue
            if kind=='public' and ' '.join(r['messages'][0]['content'].casefold().split()) in openings: continue
            seen.add(key); selected.append(r)
        if len(selected)<20 or len(valid_rows)<5: raise ValueError('Insufficient disjoint public '+kind+' records')
        result[kind] = balanced(selected,limit,kind); result[kind+'Validation'] = balanced(valid_rows,128,kind)
    return result


class Pool:
    """Uniform record sampling, then uniform rolling-window sampling; small LRU."""
    def __init__(self, rows, context, raw=False):
        self.rows = rows; self.context = context; self.raw = raw
        if not rows: raise ValueError('Empty pool')
    @lru_cache(maxsize=32)
    def get(self, index):
        row = self.rows[index]
        if self.raw:
            text = row['messages'][1]['content']
            tokens = [BOS] + list(text.encode('utf-8')) + [EOS]
            learn = [False] + [True] * (len(tokens)-1)
        else:
            tokens, learn = encode(with_owner_rules(row['messages']))
        result = list(windows(tokens, learn, self.context))
        if not result: raise ValueError('No learnable targets in record')
        return result
    def sample(self, rng):
        return rng.choice(self.get(rng.randrange(len(self.rows))))
    def validation(self, maximum=24):
        rng = random.Random(17018)
        indices = rng.sample(range(len(self.rows)), min(maximum, len(self.rows)))
        return [rng.choice(self.get(i)) for i in indices]


def training_batch(pools, stage, batch, step, seed, conversation_percent=80):
    rng = random.Random(seed+step)
    key = 'language' if stage=='foundation' else 'context'
    if stage=='conversation': key = 'public' if step % 100 < conversation_percent else 'context'
    return [pools[key].sample(rng) for _ in range(batch)], key
