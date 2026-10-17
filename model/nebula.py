"""Nebula's small, randomly initialized causal Transformer. No pretrained weights."""
import json
from dataclasses import asdict, dataclass
from pathlib import Path
import torch
from torch import nn

BOS, EOS, SYSTEM, USER, ASSISTANT, PAD = range(256, 262)
VOCAB = 262
ROLES = {"system": SYSTEM, "user": USER, "assistant": ASSISTANT}

@dataclass
class Config:
    width: int = 128
    heads: int = 4
    layers: int = 2
    context: int = 512

def config_for_preset(preset):
    presets = {
        'smoke': Config(width=64,heads=2,layers=1,context=256),
        'cpu': Config(),
        'cpu-medium': Config(width=192,heads=6,layers=4,context=1024),
        'cpu-large': Config(width=256,heads=8,layers=6,context=1024),
        'gpu': Config(width=384,heads=8,layers=6,context=2048),
    }
    if preset not in presets: raise ValueError('Unknown model preset')
    return presets[preset]

def encode(messages, answer_prefix=False):
    tokens, learn = [BOS], [False]
    for message in messages:
        role = message["role"]
        tokens.append(ROLES[role]); learn.append(False)
        content = list(message["content"].encode("utf-8"))
        tokens.extend(content); learn.extend([role == "assistant"] * len(content))
        tokens.append(EOS); learn.append(role == "assistant")
    if answer_prefix:
        tokens.append(ASSISTANT); learn.append(False)
    return tokens, learn

def pack_prompt(messages, context):
    systems = [m for m in messages if m['role'] == 'system']
    history = [m for m in messages if m['role'] != 'system']
    if not history or history[-1]['role'] != 'user': raise ValueError('A user question is required')
    prefix, _ = encode(systems)
    selected = []
    # Keep every system instruction and the full latest question; never silently cut rules.
    available = context - len(prefix) - 2
    for message in reversed(history):
        chunk = encode([message])[0][1:]
        if len(chunk) > available:
            if not selected: raise ValueError('Rules and question exceed the model context')
            break
        selected.insert(0, chunk); available -= len(chunk)
    return prefix + [token for chunk in selected for token in chunk] + [ASSISTANT]

class Nebula(nn.Module):
    def __init__(self, config):
        super().__init__(); self.config = config
        self.token = nn.Embedding(VOCAB, config.width)
        self.position = nn.Embedding(config.context, config.width)
        self.blocks = nn.ModuleList(nn.TransformerEncoderLayer(config.width, config.heads, config.width * 4, dropout=0.0, activation="gelu", batch_first=True, norm_first=True) for _ in range(config.layers))
        self.norm = nn.LayerNorm(config.width)
        self.output = nn.Linear(config.width, VOCAB, bias=False)
        self.output.weight = self.token.weight
        self.register_buffer('_causal_mask',torch.ones(config.context,config.context,dtype=torch.bool).triu(1),persistent=False)
        self.apply(self._initialize)

    @staticmethod
    def _initialize(module):
        if isinstance(module, (nn.Linear, nn.Embedding)):
            nn.init.normal_(module.weight, std=0.02)
            if isinstance(module, nn.Linear) and module.bias is not None: nn.init.zeros_(module.bias)

    def forward(self, tokens):
        length = tokens.shape[1]
        if length > self.config.context: raise ValueError("Context is too long")
        value = self.token(tokens) + self.position(torch.arange(length, device=tokens.device))
        causal = self._causal_mask[:length,:length]
        for block in self.blocks: value = block(value, src_mask=causal)
        return self.output(self.norm(value))

    @torch.inference_mode()
    def reply(self, messages, max_tokens=160, temperature=0.7):
        self.eval()
        encoded = pack_prompt(messages, self.config.context)
        device = next(self.parameters()).device
        tokens = torch.tensor([encoded], device=device)
        result = []
        for _ in range(min(max_tokens, self.config.context - len(encoded))):
            logits = self(tokens)[:, -1, :].clone()
            end = logits[:, EOS].clone(); logits[:, BOS:] = float('-inf'); logits[:, EOS] = end
            if temperature == 0: next_token = logits.argmax(-1, keepdim=True)
            else: next_token = torch.multinomial(torch.softmax(logits / temperature, -1), 1)
            value = int(next_token.item())
            if value == EOS: break
            result.append(value); tokens = torch.cat([tokens, next_token], dim=1)
        return bytes(result).decode('utf-8', errors='replace').strip()

def save(model, path, metadata, training_state=None):
    if any(not torch.isfinite(parameter).all() for parameter in model.parameters()):
        raise ValueError('Checkpoint contains non-finite weights; existing saved weights were not replaced')
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    payload={'format': 1, 'config': asdict(model.config), 'state': model.state_dict(), 'metadata': metadata}
    if training_state is not None: payload['trainingState']=training_state
    torch.save(payload, temporary)
    temporary.replace(path)

def load(path):
    data = torch.load(path, map_location='cpu', weights_only=True)
    if data.get('format') != 1: raise ValueError('Unsupported model checkpoint')
    model = Nebula(Config(**data['config'])); model.load_state_dict(data['state']); model.eval()
    if any(not torch.isfinite(parameter).all() for parameter in model.parameters()):
        raise ValueError('Checkpoint contains non-finite weights; resume from a healthy best checkpoint')
    return model, data.get('metadata', {})
