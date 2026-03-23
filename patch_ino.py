import re

with open('kyber_dilithium.ino', 'r', encoding='utf-8') as f:
    text = f.read()

# For `test_*` functions
text = re.sub(
    r'(void test_[a-zA-Z0-9_]+\(\)\s*\{)',
    r'\1\n    ScopedWorkspace local_ws;\n    if (!local_ws.ws) { Serial.println("Bellek yetersiz (OOM)!"); return; }',
    text
)

# For wipe_all_sensitive_data
text = text.replace(
    'void wipe_all_sensitive_data() {',
    'void wipe_all_sensitive_data() {\n    ScopedWorkspace local_ws;\n    if (!local_ws.ws) return;'
)

with open('kyber_dilithium.ino', 'w', encoding='utf-8') as f:
    f.write(text)
