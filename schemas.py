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

class UserCodePrompt:
    def __init__(self, code):
        self.role = "user"
        self.content = f"Code: {code}"

    def to_dict(self):
        return {"role": self.role, "content": self.content}
    
    def __repr__(self):
        return f"UserCodePrompt(role={self.role!r}, content={self.content!r})"


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
