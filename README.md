# LLM Assisted Binary Analysis


## Abstract
Briefly describe what your project does and its main goal.

## Requirements

### Package requirements
This project is developed on Python 3.12.2. 
It is suggested you create a package manager (i.e. conda)
Please install all the python libaries via
```
pip install -r requirements.txt
```

### Submodule Requirement
The one that truly matter is `sven`.
```
git submodule update --init --recursive 
```

### API Keys
This project makes call to ChatGPT4 (more may be added). Please specify your api keys in a `.env` file as shown below.

`.env`
```
OPENAI_API_KEY="api_key_here"
```

## Files
- `stats.py` - help you clean and gather statistics from scanner results
- `scan.py` - used to evaluate the capability of ChatGPT4 (by OpenAI) to detect vulnerabilities in the sven code base.
- `prompt.json` - the prompt formats to be used by `scan.py`
- `load_dataset.py` - puts the sven dataset into a mysql dataset

## Creating a Docker file to hold SVEN Database (Required for RAG + SQL_index)
### Terminal
```
docker pull mysql
docker volume create mysql_volume
docker run -d -p 3306:3306 --name=my-mysql -v mysql_volume -e MYSQL_ROOT_PASSWORD=test1234 -e MYSQL_USER=henry -e MYSQL_PASSWORD=test1234 mysql
docker ps
```

### CMD
```
python3 ./load_dataset.py --help # for more information
python3 ./load_dataset.py <dataset_dir_path>
```

## How to use scan.py

This will give you all the input parameters that you need.
Please specify the cwe_target you need. In this example, the CWE record is 190

```
scan.py --help

# generate results using the base model
python3 ./scan.py --cwe_target 190 ./cve_dataset/train ./results/scanner_rag_190.csv

# generate results using the rag + sql_index approach
python3 ./scan.py --cwe_target 190 ./cve_dataset/train ./results/scanner_rag_190.csv --is_rag True

# generate results using the llama_index
# the specific inputs for ingestion is specified as constants in ingestion.py

python3 ./ingestion.py
 ```

 Ingestion.py
 Please change the following lines accordingly
 ```
    # TODO CHANGE ME
    DEFAULT_LOG_PATH = './logs/scanner_llama_index_190.log'
    DEFAULT_RESULT_FILE_PATH = "./results/llama_index_190.csv"
    DEFAULT_CHAT_HISTORY_LOG = "./logs/{cwe_target}_chat_history.log"

    cwe_target = DEFAULT_CWE_TARGETS[1]
 ```



