import difflib
from typing import List, Optional, Dict

PROMPT_PATH = "prompt.json"

class Diff:
    """
    Used to locate how chatgpt changes the code

    Attributes:
        src: original code
        tgt: changed code (by chatgpt)
    """

    def __init__(self, src: str, tgt: str):
        self.src = src
        self.tgt = tgt
        self.d = difflib.Differ()

    def diff(self) -> List[str]:
        return self.d.compare(self.src.splitlines(), self.tgt.splitlines())
    

def get_prompt(name: str, _type: str, prompt_path: str = PROMPT_PATH) -> Optional[Dict[str, str]]:
    """
    Access the prompt

    Args:
        name: the name of the prompt
        _type: the type of the prompt
        prompt_path: the path of the prompt file

    Returns:
        a dict containing two keys: 'role' and 'content'
    """
    import json

    prompts = None
    with open(prompt_path, 'r') as f:
        prompts = json.load(f)
    assert(prompts)

    for _p in prompts:
        if _p['name'] == name and _p['type'] == _type:
            return _p['prompt']
    return None