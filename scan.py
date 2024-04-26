import argparse
import json
import logging
import os
import dotenv
import openai

dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
assert (OPENAI_API_KEY and "Pleae set api key")

DEFAULT_PROMPT_PATH = 'prompt.json'
with open(DEFAULT_PROMPT_PATH, 'r') as file:
    DEFAULT_SYSTEM_PROMPT = json.load(file)[0]["prompt"]

def setup_logger(file_path_to_scanner_log):
    """Set up the logger to log to both file and console."""
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Create handlers for file and console
    file_handler = logging.FileHandler(file_path_to_scanner_log, mode="w")
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

def call_chatgpt4(user_prompt_data, logger):
    
    # TODO Make the prompt parser able to digest multiple prompt. Currently,
    # it will only digest one
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                DEFAULT_SYSTEM_PROMPT
            ],
            api_key=OPENAI_API_KEY
        )
        return response
    except Exception as e:
        logger.error(f"An error occurred when calling openai endpoint: {e}")
    return None

def list_files(directory):
    """ List all files in a given directory """
    files = []  # List to store file names
    # Loop through the listing of the directory
    for item in os.listdir(directory):
        # TODO Check the file extension type

        full_path = os.path.join(directory, item)
        # Check if the item is a file and not a directory
        if os.path.isfile(full_path):
            files.append(full_path)  # Add the file name to the list
    return files

class UserCodePrompt:
    def __init__(self, code):
        self.role = "user"
        self.content = f"Code: {code}"

    def to_dict(self):
        return {"role": self.role, "content": self.content}

class ParsedGPTCodeResponse:
    def __init__(self, api_response):
        parsed_message = api_response["choices"][0]["message"]
        message_content = parsed_message["content"].split(',')

        self.role = parsed_message["role"]

        self.has_vul = message_content[0]
        self.vul_type = message_content[1]
        self.vul_line = message_content[2]
        self.cwe = message_content[3]
    
    def to_dict(self):
        return {
            "role": self.role,
            "has_vul": self.has_vul,
            "vul_type": self.vul_type,
            "vul_line": self.vul_line,
            "cwe": self.cwe
        }


def scan_code(file_path_to_jsonl, file_path_to_result, logger, cwe=None):
    #TODO call open api

    """Process the JSONL file and optionally log details related to a CWE."""
    logger.info(f"Training Directories: {file_path_to_jsonl}")

    CSV_ENTRY_TEMPLATE = "func_name, vul_type, true_label, pred_label"
    with open(file_path_to_result, 'w') as file:
        logger.info(CSV_ENTRY_TEMPLATE)
        file.write(CSV_ENTRY_TEMPLATE + "\n")
    
    files_to_scan = []
    # if no specific cwe is provided, scan everything
    if cwe is None:
        files_to_scan = list_files(file_path_to_jsonl)
    else:
        files_to_scan = [file_path_to_jsonl + "/{cwe}.jsonl"]

    for file in files_to_scan:
        logger.info(f"Scanning file: {file}")
        data = read_jsonl_to_json(file, logger)

        total = len(data) * 2
        total_correct_vul = 0
        total_correct = 0 

        for item in data:
            func_name = item['func_name']
            vul_code = item['func_src_before']
            fixed_code = item['func_src_after']
            vul_type = item['vul_type']

            code_with_vul = {
                vul_code: 1, 
                fixed_code: 0
            }

            for code, label in code_with_vul.items():
                api_response = call_chatgpt4(UserCodePrompt(code).to_dict, logger)
                parsed_response = ParsedGPTCodeResponse(api_response)

                is_correct_has_vul = label and parsed_response.has_vul
                is_correct_vul_type = vul_type and parsed_response.vul_type

                if is_correct_has_vul:
                    total_correct_vul += 1

                if is_correct_has_vul and is_correct_vul_type:
                    total_correct += 1

                with open(file_path_to_result, 'a') as file:
                    entry_str = f"{func_name}, {vul_type}, {label}, {parsed_response.has_vul}"
                    logger.info(entry_str)
                    file.write(entry_str + "\n")

        accuracy = total_correct_vul / total * 100
        correct_vul_type = total_correct / total * 100
        logger.info(f"Total Correct Pred: {total_correct_vul} has_vul Accuracy: {accuracy:.4f} vul_type accuracy: {correct_vul_type:.4f}")

def main():
    parser = argparse.ArgumentParser(description='Process a JSONL file and log the output.')
    parser.add_argument('file_path_to_jsonl', type=str, help='Path to the JSONL file')
    parser.add_argument('file_path_to_result', type=str, help='Path to the result file')
    parser.add_argument('--file_path_to_scanner_log', type=str, default='scanner.log', help='File path where the log should be saved')
    parser.add_argument('--CWE', type=str, default=None, help='(Optional) Specify CWE string. Defaults to all')

    args = parser.parse_args()
    logger = setup_logger(args.file_path_to_scanner_log)
    scan_code(
        args.file_path_to_jsonl, args.file_path_to_result, logger
    )


    # Processing the file with the provided arguments
    # process_file(args.file_path_to_jsonl, args.output_log_file, logger, args.CWE)

if __name__ == "__main__":
    main()
