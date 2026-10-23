import pickle
def decode_and_read(blob, root):
    value = pickle.loads(blob)
    return (root / value["path"]).read_text()
