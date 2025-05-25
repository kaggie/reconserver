import os
import pytest
from reconlibs import readoptions # generate_key is not directly used by readoptions for defaults

# Helper fixture to create a temporary config file
@pytest.fixture
def create_temp_config_file(tmp_path):
    def _create_temp_config_file(filename, content):
        config_file = tmp_path / filename
        config_file.write_text(content)
        return str(config_file)
    return _create_temp_config_file

# --- Tests for recon.opts ---

def test_read_valid_recon_opts(create_temp_config_file):
    content = """
# This is a comment about server hostname
SERVER_HOSTNAME = testserver.example.com
SERVER_PORT = 12345

SHARED_KEY = myreconsecretkey
MAX_CONCURRENT_JOBS = 3
LOG_FILEPATH = /var/log/recon.log

# Client specific settings
CLIENT_DOWNLOAD_DIR = /downloads/recon
CLIENT_DEFAULT_PFILE_NAME = P12345.7

# Boolean test
ENABLE_FEATURE_X = true
DISABLE_FEATURE_Y = false
QUOTED_STRING_EXAMPLE = "value with spaces"
ANOTHER_QUOTED = 'single quoted'
    """
    config_path = create_temp_config_file("test_recon.opts", content)
    options = readoptions(config_path)

    assert options.get("SERVER_HOSTNAME") == "testserver.example.com"
    assert options.get("SERVER_PORT") == 12345
    assert options.get("SHARED_KEY") == "myreconsecretkey"
    assert options.get("MAX_CONCURRENT_JOBS") == 3
    assert options.get("LOG_FILEPATH") == "/var/log/recon.log"
    assert options.get("CLIENT_DOWNLOAD_DIR") == "/downloads/recon"
    assert options.get("CLIENT_DEFAULT_PFILE_NAME") == "P12345.7"
    assert options.get("ENABLE_FEATURE_X") is True
    assert options.get("DISABLE_FEATURE_Y") is False
    assert options.get("QUOTED_STRING_EXAMPLE") == "value with spaces"
    assert options.get("ANOTHER_QUOTED") == "single quoted"
    assert "NON_EXISTENT_KEY" not in options

def test_default_recon_opts_creation(tmp_path):
    non_existent_file = str(tmp_path / "default_recon.opts")
    # Ensure file does not exist before test
    if os.path.exists(non_existent_file):
        os.remove(non_existent_file)

    options = readoptions(non_existent_file)

    assert os.path.exists(non_existent_file)
    # Check some key defaults from reconlibs.py
    assert options.get("SERVER_HOSTNAME") == "localhost"
    assert options.get("SERVER_PORT") == 60000
    assert options.get("SHARED_KEY") == "SET_YOUR_SHARED_KEY_HERE"
    assert options.get("MAX_CONCURRENT_JOBS") == 1
    assert options.get("LOG_FILEPATH") == "/tmp/recon_project.log"
    assert options.get("RECON_SERVER_BASE_PFILE_DIR") == "/tmp/recon_server_pfiles"
    assert options.get("CLIENT_WATCH_PATTERN") == "*.7" # Check string default with quotes in file
    assert options.get("CLIENT_DAEMON_RECON_OPTIONS_JSON") == "{}" # Check string default with quotes in file

# --- Tests for relay.opts ---

def test_read_valid_relay_opts(create_temp_config_file):
    content = """
RELAY_HOSTNAME = relay.example.com
RELAY_PORT = 55555
LOG_FILEPATH = /var/log/relay.log

# Security settings for relay
SHARED_KEY_RELAY_TO_CLIENTS = myrelaysecretkey
TRUSTED_CLIENT_IPS = 192.168.1.10,10.0.0.5

BACKEND_SERVERS = server1:60000,server2:60001
SOME_RELAY_SPECIFIC_BOOL = false
    """
    config_path = create_temp_config_file("test_relay.opts", content)
    options = readoptions(config_path)

    assert options.get("RELAY_HOSTNAME") == "relay.example.com"
    assert options.get("RELAY_PORT") == 55555
    assert options.get("LOG_FILEPATH") == "/var/log/relay.log"
    assert options.get("SHARED_KEY_RELAY_TO_CLIENTS") == "myrelaysecretkey"
    assert options.get("TRUSTED_CLIENT_IPS") == "192.168.1.10,10.0.0.5"
    assert options.get("BACKEND_SERVERS") == "server1:60000,server2:60001"
    assert options.get("SOME_RELAY_SPECIFIC_BOOL") is False

def test_default_relay_opts_creation(tmp_path):
    non_existent_file = str(tmp_path / "default_relay.opts")
    # Ensure file does not exist
    if os.path.exists(non_existent_file):
        os.remove(non_existent_file)

    options = readoptions(non_existent_file)

    assert os.path.exists(non_existent_file)
    # Check some key defaults from reconlibs.py for relay.opts
    assert options.get("RELAY_HOSTNAME") == "localhost"
    assert options.get("RELAY_PORT") == 60001
    assert options.get("LOG_FILEPATH") == "/tmp/relay_server.log"
    assert options.get("SHARED_KEY_RELAY_TO_CLIENTS") == "SET_YOUR_RELAY_TO_CLIENTS_KEY_HERE"
    assert options.get("BACKEND_SERVERS") == "localhost:60000"
    # TRUSTED_CLIENT_IPS is commented out by default, so it should be an empty string or specific default.
    # Based on current reconlibs.py, it defaults to "" if the line is commented or key not present.
    assert options.get("TRUSTED_CLIENT_IPS") == ""


# --- General Parsing Tests ---

def test_key_case_insensitivity_and_whitespace(create_temp_config_file):
    content = """
    sErVeR_HoStNaMe    =    mixedcase.server
      SERVER_PORT=9876
    ShArEd_KeY         =    spacedoutkey
    """
    config_path = create_temp_config_file("test_mixed.opts", content)
    # Assuming 'test_mixed.opts' is not 'relay.opts', it will use recon_options defaults
    options = readoptions(config_path)

    assert options.get("SERVER_HOSTNAME") == "mixedcase.server"
    assert options.get("SERVER_PORT") == 9876
    assert options.get("SHARED_KEY") == "spacedoutkey"

def test_type_inference_specifics(create_temp_config_file):
    content = """
    IS_ENABLED = true
    IS_DISABLED = false
    COUNT = 100
    NEGATIVE_COUNT = -50
    FLOAT_LIKE_INT_STR = 123.0 # Should be string as it's not pure int
    STRING_VAL = "Hello World"
    SINGLE_QUOTED_STRING = 'Test'
    UNQUOTED_STRING_WITH_SPECIAL_CHARS = value_!@#$%^&*()_+
    """
    config_path = create_temp_config_file("type_test.opts", content)
    options = readoptions(config_path)

    assert options.get("IS_ENABLED") is True
    assert options.get("IS_DISABLED") is False
    assert options.get("COUNT") == 100
    assert options.get("NEGATIVE_COUNT") == -50
    assert options.get("FLOAT_LIKE_INT_STR") == "123.0" # Not treated as int
    assert options.get("STRING_VAL") == "Hello World"
    assert options.get("SINGLE_QUOTED_STRING") == "Test"
    assert options.get("UNQUOTED_STRING_WITH_SPECIAL_CHARS") == "value_!@#$%^&*()_+"

def test_missing_file_and_subsequent_load(tmp_path):
    test_file_name = "dynamic_test.opts"
    dynamic_file_path = str(tmp_path / test_file_name)

    # Phase 1: Create and load defaults
    if os.path.exists(dynamic_file_path):
        os.remove(dynamic_file_path)
    
    default_options = readoptions(dynamic_file_path)
    assert os.path.exists(dynamic_file_path)
    original_port = default_options.get("SERVER_PORT") # Assuming recon.opts defaults

    # Phase 2: Modify the created file
    with open(dynamic_file_path, 'r')_ as f:
        lines = f.readlines()
    
    modified_lines = []
    new_port = 77777
    key_to_change = "SERVER_PORT"
    found_and_modified = False
    for line in lines:
        if line.strip().startswith(key_to_change):
            modified_lines.append(f"{key_to_change} = {new_port}\n")
            found_and_modified = True
        else:
            modified_lines.append(line)
    if not found_and_modified: # If key wasn't in default file (e.g. commented out)
         modified_lines.append(f"{key_to_change} = {new_port}\n")

    with open(dynamic_file_path, 'w') as f:
        f.writelines(modified_lines)

    # Phase 3: Reload and check modified value
    reloaded_options = readoptions(dynamic_file_path)
    assert reloaded_options.get("SERVER_PORT") == new_port
    assert reloaded_options.get("SERVER_PORT") != original_port

def test_malformed_lines_and_unknown_keys(create_temp_config_file, capsys):
    content = """
    VALID_KEY = valid_value
    MALFORMED_LINE_NO_EQUALS
    =VALUE_NO_KEY
    UNKNOWN_KEY = some_value_for_unknown_key
    ANOTHER_VALID = another_value
    """
    config_path = create_temp_config_file("malformed_test.opts", content)
    options = readoptions(config_path) # recon.opts defaults apply

    assert options.get("VALID_KEY") == "valid_value"
    assert options.get("ANOTHER_VALID") == "another_value"
    assert options.get("UNKNOWN_KEY") == "some_value_for_unknown_key" # Unknown keys should be loaded

    # Check that malformed lines do not prevent other lines from being parsed
    # And check for warnings (optional, based on readoptions implementation)
    captured = capsys.readouterr()
    # Example: if readoptions prints warnings for malformed lines
    assert "Malformed line" in captured.out # Or captured.err depending on where it prints
    assert "MALFORMED_LINE_NO_EQUALS" in captured.out
    assert "VALUE_NO_KEY" in captured.out
    
    # Check that default values for keys not in the file are still present
    assert options.get("SERVER_HOSTNAME") is not None # Example default key

def test_empty_file(create_temp_config_file):
    config_path = create_temp_config_file("empty.opts", "")
    options = readoptions(config_path) # recon.opts defaults apply

    # Should load all default values for recon.opts
    assert options.get("SERVER_HOSTNAME") == "localhost"
    assert options.get("SERVER_PORT") == 60000
    assert options.get("SHARED_KEY") == "SET_YOUR_SHARED_KEY_HERE"

def test_file_with_only_comments(create_temp_config_file):
    content = """
# This is a file with only comments
# SERVER_HOSTNAME = commented_out_server
# RELAY_PORT = 11111
    """
    config_path = create_temp_config_file("only_comments.opts", content)
    options = readoptions(config_path) # recon.opts defaults apply

    # Should load all default values for recon.opts
    assert options.get("SERVER_HOSTNAME") == "localhost"
    assert options.get("SERVER_PORT") == 60000
    assert options.get("SHARED_KEY") == "SET_YOUR_SHARED_KEY_HERE"
    assert options.get("RELAY_PORT") is None # This key is not in recon.opts defaults

def test_line_ending_variations(create_temp_config_file):
    # Test with mixed line endings (though git might normalize them)
    content_unix = "KEY_UNIX = value_unix\nKEY_MIX = value_mix\r\nKEY_WIN = value_win\r\n"
    config_path_unix = create_temp_config_file("endings_test.opts", content_unix)
    options_unix = readoptions(config_path_unix)
    assert options_unix.get("KEY_UNIX") == "value_unix"
    assert options_unix.get("KEY_MIX") == "value_mix"
    assert options_unix.get("KEY_WIN") == "value_win"

def test_integer_conversion_robustness(create_temp_config_file):
    content = """
    VALID_INT = 123
    INVALID_INT_TEXT = not_an_integer
    INT_WITH_PLUS = +456
    # PORT = 6000X # This would be a type error if not handled by int() try-except in readoptions
    # For current readoptions, non-convertible values become strings
    """
    config_path = create_temp_config_file("int_test.opts", content)
    options = readoptions(config_path)
    assert options.get("VALID_INT") == 123
    assert options.get("INVALID_INT_TEXT") == "not_an_integer" # Stays string
    assert options.get("INT_WITH_PLUS") == 456 # Python's int() handles '+'
```
