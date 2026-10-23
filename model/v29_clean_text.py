"""Conservative artifact cleanup; this does not verify source factual correctness."""
import re
import unicodedata
from collections import Counter
from ftfy import fix_text
from v18_stream import sha

MARKDOWN_DATA=re.compile(r'!\[[^\]]{0,500}\]\(\s*data:[^)]*\)',re.I)
HTML_DATA=re.compile(r"\b(?:src|href)\s*=\s*(['\"])data:.*?\1",re.I|re.S)
DATA_URI=re.compile(r'data:[^,\s]{1,150};base64,[A-Za-z0-9+/=]+',re.I)
LONG_ENCODED=re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{128,}={0,2}(?![A-Za-z0-9+/])')
SCRIPTS=re.compile(r'<(script|style)\b[^>]*>.*?</\1\s*>',re.I|re.S)


def clean_text(text,min_bytes=200):
    original=text;fixed=fix_text(text,unescape_html='auto')
    repaired=fixed!=text;text=fixed
    removed=0;edits=Counter()
    for name,pattern in [('embedded-markdown-data',MARKDOWN_DATA),('embedded-html-data',HTML_DATA),
                         ('data-uri',DATA_URI),('long-encoded-run',LONG_ENCODED),('script-style',SCRIPTS)]:
        def replace(match):
            nonlocal removed
            removed+=len(match.group());edits[name]+=1;return ' '
        text=pattern.sub(replace,text)
    kept=[];seen=Counter()
    for line in text.splitlines():
        key=' '.join(line.split())
        if len(key)>=40:
            seen[key]+=1
            if seen[key]>2:edits['repeated-long-line']+=1;continue
        kept.append(line)
    text='\n'.join(kept)
    text=re.sub(r'[ \t]+(?=\n|$)','',text) # Preserve code indentation and internal spacing.
    text=re.sub(r'\n{4,}','\n\n\n',text).strip()
    reason=None
    if removed/max(1,len(original))>.4:reason='mostly-encoded-or-script-content'
    elif len(text.encode())<min_bytes:reason='too-short-after-cleaning'
    elif '\ufffd' in text:reason='replacement-character'
    elif any(ord(c)<32 and c not in '\n\t' for c in text):reason='control-character'
    elif any(marker in text for marker in ['\u00e2\u20ac','\u00ef\u00bf\u00bd','\u00c3\u00a9','\u00c3\u00bc']):reason='unrepaired-mojibake'
    normalized=' '.join(unicodedata.normalize('NFKC',text).casefold().split())
    return (None if reason else text),dict(reason=reason,encodingRepaired=repaired,edits=dict(edits),
        originalUtf8Bytes=len(original.encode()),cleanedUtf8Bytes=len(text.encode()),
        normalizedHash=sha(normalized.encode()))
