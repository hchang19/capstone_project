import dotenv
import os
import json
from langchain_community.utilities.sql_database import SQLDatabase

from langchain_community.vectorstores import FAISS
from langchain_core.example_selectors import SemanticSimilarityExampleSelector
from langchain_openai import OpenAIEmbeddings

from langchain_community.agent_toolkits import create_sql_agent
from langchain_openai import ChatOpenAI

from utils import setup_logger
from db_info import (
    DEFAULT_DB_HOST, DEFAULT_DB_NAME, DEFAULT_DB_TABLE,
    DEFAULT_DB_PORT, DEFAULT_DB_PWD, DEFAULT_DB_USER, DEFAULT_DB_DRIVER
)

from langchain_core.prompts import (
    ChatPromptTemplate,
    FewShotPromptTemplate,
    MessagesPlaceholder,
    PromptTemplate,
    SystemMessagePromptTemplate,
)


dotenv.load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
assert (OPENAI_API_KEY and "Pleae set api key")

DEFAULT_LOG_PATH = 'rag.log'
DEFAULT_USER_QUERY_PATH = 'user_queries.json'

def parse_response(api_response):
    response_object = json.loads(api_response)
    print(response_object.keys())
    return response_object['input'], response_object['output']


def call_rag_query(user_input, logger = None):
    if logger is None:
        logger = setup_logger(DEFAULT_LOG_PATH)

    # connect to the database
    mysql_uri = "{0}://{1}:{2}@{3}:{4}/{5}".format(
        DEFAULT_DB_DRIVER, DEFAULT_DB_USER, DEFAULT_DB_PWD,
        DEFAULT_DB_HOST, DEFAULT_DB_PORT, DEFAULT_DB_NAME
    )
    db = SQLDatabase.from_uri(mysql_uri)
    logger.info(f"Successfully connected to {DEFAULT_DB_HOST}:{DEFAULT_DB_PORT}")

    print(db.get_usable_table_names())

    # create the open ai connection / query generation
    llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)

    # setup the agent for better responses
    # grab the queries examples
    logger.info(f'Reading example user queries from {DEFAULT_USER_QUERY_PATH}')
    with open('user_queries.json', 'r') as file:
        query_examples = json.load(file)
    logger.info(f'Successfully read example user queries. {query_examples[0]}')

    example_selector = SemanticSimilarityExampleSelector.from_examples(
        query_examples,
        OpenAIEmbeddings(),
        FAISS,
        k=3,
        input_keys=["input"],
    )


    system_prefix = """You are an agent designed to interact with a SQL database.
    Given an input question, create a syntactically correct {dialect} query to run, then look at the results of the query and return the answer.
    Unless the user specifies a specific number of examples they wish to obtain, always limit your query to at most {top_k} results.
    You can order the results by a relevant column to return the most interesting examples in the database.
    Never query for all the columns from a specific table, only ask for the relevant columns given the question.
    You have access to tools for interacting with the database.
    Only use the given tools. Only use the information returned by the tools to construct your final answer.
    You MUST double check your query before executing it. If you get an error while executing a query, rewrite the query and try again.

    DO NOT make any DML statements (INSERT, UPDATE, DELETE, DROP etc.) to the database.

    If the question does not seem related to the database, just return "I don't have information on this topic" as the answer.

    Here are some examples of user inputs and their corresponding SQL queries:"""

    few_shot_prompt = FewShotPromptTemplate(
        example_selector=example_selector,
        example_prompt=PromptTemplate.from_template(
            "User input: {input}\nSQL query: {query}"
        ),
        input_variables=["input", "dialect", "top_k"],
        prefix=system_prefix,
        suffix="",
    )

    full_prompt = ChatPromptTemplate.from_messages(
        [
            SystemMessagePromptTemplate(prompt=few_shot_prompt),
            ("human", "{input}"),
            MessagesPlaceholder("agent_scratchpad"),
        ]
    )

    # user input
    agent_executor = create_sql_agent(llm, db=db, agent_type="openai-tools", prompt=full_prompt, verbose=True)
    logger.info(f"Successfully created agent executor")

    # TODO UNCOMMENT THIS IF YOU CARE ABOUT WHICH QUERIES ARE USED

    # prompt_val = full_prompt.invoke(
    #     {
    #         "input": "How many arists are there",
    #         "top_k": 3,
    #         "dialect": "SQLite",
    #         "agent_scratchpad": [],
    #     }
    # )
    # print(prompt_val.to_string())

    api_response = agent_executor.invoke({
        "input": user_input
    })
    
    api_input, api_output = api_response['input'], api_response['output']
    logger.info(f"Input Format: {api_input}")
    logger.info(f"Output: {api_output}")
    return api_output


if __name__ == "__main__":
    user_input = input("What will you like to ask?")
    rag_query(user_input)