import nest_asyncio
import random
from tqdm import tqdm
from utils import (
    get_open_ai_key, list_jsonl_files,
    read_jsonl_to_json, setup_logger, get_dataset_json_schema,
    write_json_file, filter_json
)
from ingestion_tools import (
    get_json_tools
)
from llama_index.core import Settings
from llama_index.llms.openai import OpenAI
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.core import VectorStoreIndex
from llama_index.core.objects import ObjectIndex
from llama_index.agent.openai import OpenAIAgentWorker
from llama_index.core.agent import AgentRunner

from openai import BadRequestError

random.seed(2048)
DEFAULT_LOG_PATH = './logs/scanner_llama_index_190.log'
DEFAULT_DATASET_DIR_PATH = "./cve_dataset"
DEFAULT_CHAT_HISTORY_LOG = "./logs/{cwe_target}_chat_history.log"

DEFAULT_QUERY_MODEL = "gpt-4-turbo"
DEFAULT_EMBEDDING_MODEL = "text-embedding-ada-002"

DEFAULT_RESULT_FILE_PATH = "./results/llama_index_190.csv"

DEFAULT_AGENT_PROMPT = """
When I give you a function, I want you to get the tools related to function name to answer the questino.
If 'changes' or 'line changes' are requested for a function, please query 'line_changes' for the related function tool.

When given a code snippet and the vulnerability to check for, do the following:
1.) Scan the code for the specified cwe_vulnerability.
2.) Use the details to get "details" about the code snippet. This include "before code", "after code", and "vul_type".
3.) Use the change_tool to get "line changes" associated with the function.
4.) Finally, using the gathered information return 1 if the snippet has the specific vulnerability. Otherwise return 0.

The CWE Record you are testing is (cwe-{cwe_target})
Do not return with any thing else aside from 1 or 0. You can return -1 if you are unsure.
"""

# DEFAULT_AGENT_PROMPT = """
# The CWE Record you are testing is (cwe-{cwe_target})
# Scan the code snippet and return the function name
# """

DEFAULT_CWE_TARGETS = ["787", "190", "125"]
"""
CWE-787: Writing data outside the bounds of allocated memory.
CWE-190: Arithmetic operation results in a value that exceeds the maximum for the data type.
CWE-125: Reading data outside the bounds of allocated memory.
"""

def load_json(dataset_dir_path, cwe_target=None, logger=None, create_json=False):
    dataset_train_path = f"{dataset_dir_path}/train"

    target_cwe_dir = f"{dataset_dir_path}/cwe_{cwe_target}"
    files_to_load = list_jsonl_files(dataset_train_path, logger)
    
    cwe_json_values = []
    if cwe_target is not None:
        files_to_load = [file for file in files_to_load if cwe_target in file]

    for file in files_to_load:
        logger.info(f"Scanning file: {file}")
        data = read_jsonl_to_json(file, logger)
        cwe_json_values += data

        if create_json:
            for i, line in enumerate(data):
                target_file_name = f"{target_cwe_dir}/record_{i}.json"
                write_json_file(target_file_name, line, logger)
    return cwe_json_values

def create_ingestion_tools(dataset_dir_path, cwe_target, cwe_json_values, logger=None):
    initial_tools = []
    target_cwe_dir = f"{dataset_dir_path}/cwe_{cwe_target}"

    # split the json into two different schema to accomadate
    # for the max context length of ada embedding
    json_fnc_schema_path = f"{dataset_dir_path}/record_small_schema.json"
    json_change_schema_path = f"{dataset_dir_path}/record_change_schema.json"

    json_fnc_schema = get_dataset_json_schema(json_fnc_schema_path, logger)
    json_changes_schema = get_dataset_json_schema(json_change_schema_path, logger)
    json_fnc_required = json_fnc_schema["required"]
    json_changes_required = json_changes_schema["required"]
    
    
    for i, json_value in tqdm(enumerate(cwe_json_values), desc="Creating tools"):
        target_json_file = f"{target_cwe_dir}/record_{i}.json"

        json_fnc_values = filter_json(json_value, json_fnc_required)
        json_changes_values = filter_json(json_value, json_changes_required)
        
        curr_tools = get_json_tools(
            json_fnc_schema, json_changes_schema, 
            json_fnc_values, json_changes_values,
            target_json_file
        )
        initial_tools.append(curr_tools)
    return initial_tools

def create_agent(initial_tools, cwe_target, verbose=True):
    # the initial tools are bundled per the record
    # want to index the tools for easier agent retrieval
    all_tools = [tool for tool_bundle in initial_tools for tool in tool_bundle]
    obj_index = ObjectIndex.from_objects(
        all_tools,
        index_cls=VectorStoreIndex,
    )

    obj_retriever = obj_index.as_retriever(similarity_top_k=4)
    agent_worker = OpenAIAgentWorker.from_tools(
        tool_retriever=obj_retriever,
        system_prompt=DEFAULT_AGENT_PROMPT.format(cwe_target=cwe_target),
        verbose=verbose
    )
    agent = AgentRunner(agent_worker)
    return agent

def evaulate_agent(agent, cwe_json_values, file_path_to_result):

    # create the dataset to query the agent
    eval_dataset = []
    for item in cwe_json_values:
        func_name = item['func_name']
        vul_code = item['func_src_before']
        fixed_code = item['func_src_after']

        eval_dataset.append(
            (func_name, vul_code, 1)
        )
        eval_dataset.append(
            (func_name, fixed_code, 0)
        )
    random.shuffle(eval_dataset)
    with open(file_path_to_result, 'w') as file:
        for func_name, code, label in eval_dataset:
            try:
                response = agent.query(
                    "For the given code snippet, check if you have any vulnerability patch associated with it. "
                    "Get patch details and line changes and determine if the code has a vulnerability. "
                    f"Code: \n{code}"
                )
                entry_str = f"{func_name},{response}, {label}"
                logger.info(entry_str)
                file.write(entry_str + "\n")
            except BadRequestError as e:
                logger.error(f"Error occured with {func_name}: {e}")
                continue
            except ValueError as e:
                logger.error(f"function tool error occured with {func_name}: {e}")
                continue


def store_chat_history_to_log(cwe_target, chat_history):
    chat_history_log_path = DEFAULT_CHAT_HISTORY_LOG.format(cwe_target=cwe_target)
    with open(chat_history_log_path, 'w') as file:
        for line in chat_history:
            file.write(str(line))


def ingest_cwe_dataset(cwe_target=None, logger=None):
    cwe_json_values = load_json(DEFAULT_DATASET_DIR_PATH, cwe_target, logger)
    logger.info(f"Data for cwe-{cwe_target} loaded successfully. Record Count: {len(cwe_json_values)}")
    
    initial_tools = create_ingestion_tools(
        DEFAULT_DATASET_DIR_PATH, cwe_target,
        cwe_json_values, logger
    )
    
    logger.info(f"Successfully created {len(initial_tools)} tools for cwe_{cwe_target}")

    agent = create_agent(initial_tools, cwe_target, verbose=True)
    logger.info(
        f"Successfully created agent with the given prompt: \n {DEFAULT_AGENT_PROMPT.format(cwe_target=cwe_target)}"
    )

    evaulate_agent(agent, cwe_json_values, DEFAULT_RESULT_FILE_PATH)
    logger.info(
        f"Finished evaluation the llm. Storing chat history"
    )
    store_chat_history_to_log(cwe_target, agent.chat_history)
    



if __name__ == "__main__":
    # load the api key
    get_open_ai_key()
    nest_asyncio.apply()
    cwe_target = DEFAULT_CWE_TARGETS[1]

    Settings.llm = OpenAI(model=DEFAULT_QUERY_MODEL)
    Settings.embed_model = OpenAIEmbedding(model=DEFAULT_EMBEDDING_MODEL)

    logger = setup_logger(DEFAULT_LOG_PATH)
    ingest_cwe_dataset(cwe_target, logger)