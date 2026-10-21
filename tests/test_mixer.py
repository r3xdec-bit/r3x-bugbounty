import os
import tempfile
from pathlib import Path
from r3x.mixer.key_store import KeyStore
from r3x.mixer.models import TaskRole, DEFAULT_PROVIDERS
from r3x.mixer.router import ModelRouter

def test_keystore_encryption_and_crud():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        vault_path = Path(tf.name)

    try:
        ks = KeyStore(vault_path=vault_path)
        entry1 = ks.add_key("nvidia", "nvapi-test-secret-key-12345", label="primary")
        assert entry1.provider == "nvidia"
        assert entry1.mask() == "nvap...2345"

        # Ensure encrypted file does NOT contain plaintext key
        with open(vault_path, "rb") as f:
            raw_content = f.read()
        assert b"nvapi-test-secret-key-12345" not in raw_content

        # Reload keystore to test decryption
        ks2 = KeyStore(vault_path=vault_path)
        keys = ks2.get_keys("nvidia")
        assert len(keys) == 1
        assert keys[0].key_value == "nvapi-test-secret-key-12345"

        # Rotation / success / fail marking
        ks2.mark_key_failure(entry1.key_id)
        assert ks2.get_keys("nvidia")[0].failed_count == 1
        ks2.mark_key_success(entry1.key_id)
        assert ks2.get_keys("nvidia")[0].failed_count == 0

        # Remove key
        assert ks2.remove_key(entry1.key_id) is True
        assert len(ks2.get_keys("nvidia")) == 0

    finally:
        if vault_path.exists():
            os.remove(vault_path)

def test_model_router_cost_calculation():
    router = ModelRouter()
    # nvidia costs: in: 0.70/1M, out: 0.90/1M
    cost = router._calculate_cost("nvidia", p_tok=1000, c_tok=500)
    expected = (1000 / 1_000_000 * 0.70) + (500 / 1_000_000 * 0.90)
    assert abs(cost - expected) < 1e-6
