import argparse
import json
import os
import dotenv
from openai import OpenAI

from utils import read_jsonl_to_json, list_jsonl_files, setup_logger
from schemas import UserQueryPromptWrapper
from rag import call_rag_query

dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
assert (OPENAI_API_KEY and "Pleae set api key")

DEFAULT_PROMPT_PATH = 'prompt.json'
with open(DEFAULT_PROMPT_PATH, 'r') as file:
    DEFAULT_SYSTEM_PROMPT = json.load(file)

DEFAULT_QUERY_MODEL = "gpt-4-turbo"
DEFAULT_LOG_FILE = "./logs/scanner_rag_190.log"

def call_chatgpt4(user_query, logger):
    
    # TODO Make the prompt parser able to digest multiple prompt. Currently,
    # it will only digest one
    try:
        client = OpenAI(
            api_key=OPENAI_API_KEY,
        )

        system_prompt = DEFAULT_SYSTEM_PROMPT[0]["prompt"]

        user_query_prompt = UserQueryPromptWrapper(user_query).to_dict()
        logger.info(system_prompt)
        logger.info(user_query_prompt['content'])
        response = client.chat.completions.create(
            messages=[
                system_prompt,
                user_query_prompt
            ],
            model=DEFAULT_QUERY_MODEL,
        )
        return response
    except Exception as e:
        logger.error(f"An error occurred when calling openai endpoint: {e}")
    return None


def scan_code(file_path_to_jsonl, file_path_to_result, logger, cwe_target, is_rag=False):
    """Process the JSONL file and optionally log details related to a CWE."""

    # create the header for the csv result
    CSV_ENTRY_TEMPLATE = "func_name, pred_label, true_label"
    with open(file_path_to_result, 'w') as file:
        logger.info(CSV_ENTRY_TEMPLATE)
        file.write(CSV_ENTRY_TEMPLATE + "\n")
    
    # if no specific cwe is provided, scan everything
    files_to_scan = list_jsonl_files(file_path_to_jsonl, logger)
    if cwe_target is not None:
        files_to_scan = [file for file in files_to_scan if cwe_target in file]

    logger.info(f"Calling the {DEFAULT_QUERY_MODEL}")

    for file in files_to_scan:
        logger.info(f"Scanning file: {file}")
        data = read_jsonl_to_json(file, logger)

        for item in data:
            func_name = item['func_name']
            vul_code = item['func_src_before']
            fixed_code = item['func_src_after']

            code_with_vul = {
                vul_code: 1, 
                fixed_code: 0
            }

            for code, true_label in code_with_vul.items():
                # TODO select the proper item for sql based
                # use this for the sql part
                user_query_content = f"The cwe_target vulnerability is {cwe_target}. Here is the code: \n {code}"

                predicted_label = -1
                if is_rag:
                    rag_instruction = DEFAULT_SYSTEM_PROMPT[1]["prompt"]["content"]
                    # enhance the query instruction with the rag
                    user_query_content = rag_instruction + user_query_content
                    predicted_label = call_rag_query(user_query_content, logger)
                else:
                    api_response = call_chatgpt4(user_query_content, logger)
                    
                    logger.info(user_query_content)
                    predicted_label = api_response.choices[0].message.content

                with open(file_path_to_result, 'a') as file:
                    entry_str = f"{func_name}, {predicted_label}, {true_label}"
                    logger.info(entry_str)
                    file.write(entry_str + "\n")

def main():
    parser = argparse.ArgumentParser(description='Process a JSONL file and log the output.')
    parser.add_argument('file_path_to_jsonl', type=str, help='Path to the JSONL file')
    parser.add_argument('file_path_to_result', type=str, help='Path to the result file')
    parser.add_argument('--file_path_to_scanner_log', type=str, default=DEFAULT_LOG_FILE, help='File path where the log should be saved')
    parser.add_argument('--cwe_target', type=str, default=None, help='(Optional) Specify CWE string. Defaults to all')
    parser.add_argument('--is_rag', type=bool, default=False, help="Specify whether to use the rag")
    args = parser.parse_args()
    logger = setup_logger(args.file_path_to_scanner_log)
    scan_code(
        args.file_path_to_jsonl, args.file_path_to_result, logger, cwe_target=args.cwe_target, is_rag=args.is_rag
    )

if __name__ == "__main__":
    main()
    
