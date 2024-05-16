# Create / connect to the default database
# Load the sven dataset
import argparse
import mysql.connector
from mysql.connector import Error

from schemas import SvenDataRow
from db_info import (
    DEFAULT_DB_HOST, DEFAULT_DB_NAME, DEFAULT_DB_TABLE,
    DEFAULT_DB_PORT, DEFAULT_DB_PWD, DEFAULT_DB_USER,
)
from utils import read_jsonl_to_json, list_jsonl_files, setup_logger

DEFAULT_LOG_PATH = 'load_dataset.log'


def parse_arguments():
    parser = argparse.ArgumentParser(description='Specify the path of the folder that contains the jsonl files into a specified mysql container')
    parser.add_argument('dataset_dir_path', type=str, help='Path to the JSONL file')
    parser.add_argument('--cwe', type=str, default=None, help='(Optional) Specify CWE string. Defaults to all')
    parser.add_argument('--logger_path', type=str, default=DEFAULT_LOG_PATH, help='(Optional) Specify log file. Defaults to load_dataset.py')
    
    args = parser.parse_args()
    return args


def main():
    args = parse_arguments()
    # open up the args
    dataset_dir_path = args.dataset_dir_path
    cwe_filter = args.cwe
    logger_path = args.logger_path

    logger = setup_logger(logger_path)
    try:
        cnx = mysql.connector.connect(
            host=DEFAULT_DB_HOST,
            port=DEFAULT_DB_PORT,
            user=DEFAULT_DB_USER,
            password=DEFAULT_DB_PWD
        )

        if cnx.is_connected():
            logger.info(f"Connected to mysql")

        cursor = cnx.cursor()

        # create a database for the sven data
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DEFAULT_DB_NAME}")
        logger.info(f"Database '{DEFAULT_DB_NAME}' created or already exists.")

        cnx.database = DEFAULT_DB_NAME
        logger.info(f"Connected to {DEFAULT_DB_NAME}")

        # create the table with schema
        table_name = DEFAULT_DB_TABLE
        table_schema = """
        func_id VARCHAR(255) PRIMARY KEY,
        func_name VARCHAR(255) NOT NULL,
        vul_type VARCHAR(255) NOT NULL,
        func_src_before TEXT NOT NULL,
        func_src_after TEXT NOT NULL,
        line_changes TEXT NOT NULL,
        char_changes TEXT NOT NULL,
        commit_link VARCHAR(255) NOT NULL,
        file_name VARCHAR(255) NOT NULL
        
        """
            
        # Create table if it doesn't exist
        create_table_sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({table_schema})"
        cursor.execute(create_table_sql)
        logger.info(f"Table '{table_name}' created or already exists.")
        
        files_to_load = list_jsonl_files(dataset_dir_path, logger)

        if cwe_filter is not None:
            files_to_load = [file for file in files_to_load if cwe_filter in file]

        for file in files_to_load:
            logger.info(f"Scanning file: {file}")
            data = read_jsonl_to_json(file, logger)
            for i in range(len(data)):
                row = data[i]
                row["func_id"] = f"{row['vul_type']}_{i}"
                formatted_row = SvenDataRow.from_dict(row)
                cmd_str, row_data = formatted_row.generate_insert_data(table_name)
                cursor.execute(cmd_str, row_data)

        cnx.commit()
        cursor.close()
        cnx.close()
    except Error as err:
        logger.error(f"An Error occursed when initializing the MySql Connection: {err}")




if __name__ == "__main__":
    main()










