"""code_snippet must never carry a credential value into the serialized report."""

import json

from aibom_scanner.detectors.ai_sdk import scan_file
from aibom_scanner.detectors.secrets import mask_secrets
from aibom_scanner.formatters.json_fmt import format_json
from aibom_scanner.formatters.sarif_fmt import format_sarif
from aibom_scanner.formatters.table_fmt import format_table
from aibom_scanner.scanner import scan_directory

# Assembled at runtime so no key-shaped literal sits in this file.
KEY_SHAPED = "sk-" + "ant-" + "A" * 48
NO_SHAPE = "plainvalue" + "-xyz-" + "98765"


def _repo(tmp_path):
    (tmp_path / "app.py").write_text(
        "import anthropic\n"
        f'c2 = anthropic.messages.Client(api_key="{KEY_SHAPED}")\n'
        f'c3 = anthropic.messages.Client(api_key="{NO_SHAPE}")\n'
    )
    return tmp_path


class TestSnippets:
    def test_detection_kept_and_values_masked(self):
        src = f'import os\nc2 = anthropic.messages.Client(api_key="{KEY_SHAPED}", access_token="{NO_SHAPE}")\n'
        dets = [d for d in scan_file("app.py", src) if d.line_number == 2]
        assert dets and all(KEY_SHAPED not in d.code_snippet and NO_SHAPE not in d.code_snippet for d in dets)
        assert (dets[0].provider, dets[0].file_path, dets[0].line_number) == ("anthropic", "app.py", 2)
        assert 'api_key="<redacted>"' in dets[0].code_snippet

    def test_no_value_in_any_detection_or_other_format(self, tmp_path):
        result = scan_directory(_repo(tmp_path))
        assert any(d["provider"] == "anthropic" and d["line_number"] == 2 for d in result.detections)
        assert KEY_SHAPED not in json.dumps(result.detections) and NO_SHAPE not in json.dumps(result.detections)
        for output in (format_json(result), format_sarif(result), format_table(result)):
            assert KEY_SHAPED not in output and NO_SHAPE not in output

    def test_secrets_drop_raw_value_but_keep_redacted_value(self, tmp_path):
        result = scan_directory(_repo(tmp_path))
        hardcoded = [s for s in result.secrets if s["evidence_type"] == "hardcoded_key"]
        assert hardcoded and all("raw_value" not in s for s in result.secrets)
        assert all(s["redacted_value"] and s["redacted_value"] != KEY_SHAPED for s in hardcoded)
        assert all(len(s["redacted_value"]) == 9 for s in hardcoded)  # 4 + "..." + 2
        assert '"raw_value"' not in format_json(result)

    def test_env_lookups_are_left_intact(self):
        for line in ('c = anthropic.messages.Client(api_key=os.environ["ANTHROPIC_API_KEY"])',
                     "c = anthropic.messages.Client(api_key=os.getenv('ANTHROPIC_API_KEY'))",
                     "const k = process.env.ANTHROPIC_API_KEY"):
            assert mask_secrets(line) == line

    def test_masks_quoted_credential_names(self):
        assert mask_secrets('headers = {"Authorization": "Bearer abcdefgh1234"}') == \
            'headers = {"Authorization": "<redacted>"}'
        assert mask_secrets("password = 'short'") == "password = 'short'"
        assert mask_secrets('db_password="hunter2hunter2"') == 'db_password="<redacted>"'

    def test_evidence_qualifier_keywords_survive(self):
        line = 'resp = anthropic.messages.create(user_input, api_key="' + NO_SHAPE + '")'
        assert "user_input" in mask_secrets(line)
