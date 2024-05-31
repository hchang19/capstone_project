# TODO: abstract all of this into a function that takes in a PDF file name 

from llama_index.core import SimpleDirectoryReader, VectorStoreIndex, SummaryIndex
from llama_index.core.node_parser import SentenceSplitter, JSONNodeParser
from llama_index.core.indices.struct_store import JSONQueryEngine
from llama_index.core.tools import FunctionTool, QueryEngineTool
from llama_index.core.vector_stores import MetadataFilters, FilterCondition
from typing import List, Optional

import re


def enforce_fnc_name(tool_name):
    # openAI has a specific format for tool names that must be enforced
    # Check if function_name matches the pattern
    pattern = r'[^a-zA-Z0-9_-]'
    return re.sub(pattern, '', tool_name)

def get_doc_tools(
    file_path: str,
    name: str,
) -> str:
    """Get vector query and summary query tools from a document."""

    # load documents
    documents = SimpleDirectoryReader(input_files=[file_path]).load_data()
    splitter = SentenceSplitter(chunk_size=1024)
    nodes = splitter.get_nodes_from_documents(documents)
    vector_index = VectorStoreIndex(nodes)
    
    def vector_query(
        query: str, 
        page_numbers: Optional[List[str]] = None
    ) -> str:
        """Use to answer questions over a given paper.
    
        Useful if you have specific questions over the paper.
        Always leave page_numbers as None UNLESS there is a specific page you want to search for.
    
        Args:
            query (str): the string query to be embedded.
            page_numbers (Optional[List[str]]): Filter by set of pages. Leave as NONE 
                if we want to perform a vector search
                over all pages. Otherwise, filter by the set of specified pages.
        
        """
    
        page_numbers = page_numbers or []
        metadata_dicts = [
            {"key": "page_label", "value": p} for p in page_numbers
        ]
        
        query_engine = vector_index.as_query_engine(
            similarity_top_k=2,
            filters=MetadataFilters.from_dicts(
                metadata_dicts,
                condition=FilterCondition.OR
            )
        )
        response = query_engine.query(query)
        return response
        
    
    vector_query_tool = FunctionTool.from_defaults(
        name=f"vector_tool_{name}",
        fn=vector_query
    )
    
    summary_index = SummaryIndex(nodes)
    summary_query_engine = summary_index.as_query_engine(
        response_mode="tree_summarize",
        use_async=True,
    )
    summary_tool = QueryEngineTool.from_defaults(
        name=f"summary_tool_{name}",
        query_engine=summary_query_engine,
        description=(
            f"Useful for summarization questions related to {name}"
        ),
    )

    return vector_query_tool, summary_tool

def get_json_tools(
    json_fnc_schema, json_changes_schema, 
    json_fnc_values, json_changes_values,
    input_file):

    # # load the document and text information
    # documents = JSONReader(
    #     levels_back=0
    # ).load_data(input_file=input_file)
    # print(documents)
    # splitter = SentenceSplitter(chunk_size=1024)
    # nodes = splitter.get_nodes_from_documents(documents)

    # # index component
    # vector_index = VectorStoreIndex(nodes)
    # summary_index = SummaryIndex(nodes)

    # # create the query engines
    # summary_query_engine = summary_index.as_query_engine(
    #     response_mode="tree_summarize",
    #     use_async=True,
    # )
    # vector_query_engine = vector_index.as_query_engine()
    function_name = enforce_fnc_name(json_fnc_values["func_name"])
    json_fnc_query_engine = JSONQueryEngine(
        json_value=json_fnc_values,
        json_schema=json_fnc_schema,
        function_name=f"{function_name}_details_fnc"
    )

    json_changes_query_engine = JSONQueryEngine(
        json_value=json_changes_values,
        json_schema=json_changes_schema,
        function_name=f"{function_name}_changes_fnc",
    )

    # # transform the engine into tools
    # summary_tool = QueryEngineTool.from_defaults(
    #     query_engine=summary_query_engine,
    #     description=(
    #         "Useful for summarization questions about the vulnerability patch"
    #     ),
    # )

    # vector_tool = QueryEngineTool.from_defaults(
    #     query_engine=vector_query_engine,
    #     description=(
    #         "Useful for retrieving specific context about the vulnerability patch."
    #     ),
    # )

    json_fnc_tool = QueryEngineTool.from_defaults(
        query_engine=json_fnc_query_engine,
        name=f"{function_name}_details_tool",
        description=(
            f"Useful for retrieving specific information about the function before and after the vulnerability patch for function {function_name}"
        )
    )

    json_changes_tool = QueryEngineTool.from_defaults(
        query_engine=json_changes_query_engine,
        name=f"{function_name}_changes_tool",
        description=(
            f"Useful for retrieving specific information about the line changes of the vulnerability patch for function {function_name}"
        )
    )

    return json_fnc_tool, json_changes_tool
