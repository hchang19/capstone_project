from dataclasses import dataclass
from typing import Dict

@dataclass
class SvenDataRow:
    func_id: str
    func_name: str
    func_src_before: str
    func_src_after: str
    line_changes: str
    char_changes: str
    commit_link: str
    file_name: str
    vul_type: str

    @classmethod
    def from_dict(cls, row: Dict[str, any]):
        return cls(
            func_id=row.get('func_id', ""),
            func_name=row.get('func_name', ""),
            func_src_before=row.get('func_src_before', ""),
            func_src_after=row.get('func_src_after', ""),
            line_changes=str(row.get('line_changes', "")),
            char_changes=str(row.get('char_changes', "")),
            commit_link=row.get('commit_link', ""),
            file_name=row.get('file_name', ""),
            vul_type=row.get('vul_type', ""),
        )

    def generate_insert_data(self, table_name):
        cmd_str = (
            f"INSERT IGNORE INTO {table_name} (func_id, func_name, func_src_before, func_src_after, line_changes, char_changes, commit_link, file_name, vul_type) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)")
        data = (self.func_id, self.func_name, self.func_src_before, self.func_src_after, self.line_changes, self.char_changes, self.commit_link, self.file_name, self.vul_type)
        return cmd_str, data

def safe_get(list, index):
    try:
        return list[index]
    except IndexError:
        return None

class UserCodePrompt:
    def __init__(self, code):
        self.role = "user"
        self.content = f"Code: {code}"

    def to_dict(self):
        return {"role": self.role, "content": self.content}
    
    def __repr__(self):
        return f"UserCodePrompt(role={self.role!r}, content={self.content!r})"

class ParsedGPTCodeResponse:
    def __init__(self, role, has_vul, vul_type, vul_line, cwe):
        self.role = role

        self.has_vul = has_vul
        self.vul_type = vul_type
        self.vul_line = vul_line
        self.cwe = cwe
    
    @classmethod
    def from_gpt(cls, api_response):
        parsed_message = api_response["choices"][0]["message"]
        message_content = parsed_message["content"].split(',')

        return cls(
            parsed_message["role"],
            message_content[0],
            message_content[1],
            message_content[2],
            message_content[3]
        )
    
    @classmethod
    def from_str(cls, api_response_str):
        parsed_api_response = api_response_str.split(',')
        return cls(
            'user',
            safe_get(parsed_api_response, 0),
            safe_get(parsed_api_response, 1),
            safe_get(parsed_api_response, 2),
            safe_get(parsed_api_response, 3)
        )
        
    def to_dict(self):
        return {
            "role": self.role,
            "has_vul": self.has_vul,
            "vul_type": self.vul_type,
            "vul_line": self.vul_line,
            "cwe": self.cwe
        }
