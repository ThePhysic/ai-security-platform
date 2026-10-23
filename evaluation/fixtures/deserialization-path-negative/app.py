import json
def decode_and_read(blob, root):
    value = json.loads(blob)
    if value["name"] not in {"public.txt"}:
        raise ValueError()
    return (root / value["name"]).read_text()
