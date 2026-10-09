# Tests always run on the built-in defaults, so editing config.yaml
# can't make them fail. This runs before any test module is imported.
import os

os.environ["HORUS_CONFIG"] = "no-config-file-for-tests.yaml"