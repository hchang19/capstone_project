import difflib
from typing import List, Optional, Dict
import os
import json
import logging

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


def setup_logger(file_path_to_log):
    """Set up the logger to log to both file and console."""
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Create handlers for file and console
    file_handler = logging.FileHandler(file_path_to_log, mode="w")
    console_handler = logging.StreamHandler()

    # Set logging level for handlers
    file_handler.setLevel(logging.INFO)
    console_handler.setLevel(logging.DEBUG)

    # Create a formatter and add it to handlers
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def read_jsonl_to_json(filename, logger):
    """Reads a JSONL file and returns a list of dictionaries, logs errors if any."""
    data = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.error(f"Error decoding JSON from line: {line.strip()} - Error: {str(e)}")
        return data
    except FileNotFoundError as e:
        logger.error(f"File not found: {filename} - Error: {str(e)}")
    except Exception as e:
        logger.error(f"An error occurred while reading the file: {filename} - Error: {str(e)}")


def list_jsonl_files(directory, logger):
    """ List all jsonl files in a given directory """
    files = []  # List to store file names
    # Loop through the listing of the directory
    for file_name in os.listdir(directory):

        full_path = os.path.join(directory, file_name)
        # Check if the item is a file and not a directory
        if os.path.isfile(full_path):
            files.append(full_path)  # Add the file name to the list

        if not file_name.endswith('.jsonl'):
            continue

    return files