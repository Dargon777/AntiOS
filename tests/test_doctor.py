from antios.doctor import diagnose


def _scan(*, generation="Windows 11", secure_boot=True, tpm_present=True, tpm_ready=True):
    return {
        "system": {
            "windows": {
                "generation": generation,
                "full_build": "26100.1",
            },
            "security": {
                "secure_boot": {"enabled": secure_boot},
                "tpm": {
                    "present": tpm_present,
                    "ready": tpm_ready,
                    "enabled": tpm_present,
                    "activated": tpm_present,
                },
            },
            "runtime": {"python": "3.13.1"},
        },
        "registry": [],
    }


def test_doctor_healthy_system_is_zero_exit():
    result = diagnose(_scan())

    assert result["exit_code"] == 0
    assert result["summary"]["warn"] == 0
    assert any(item["id"] == "secure-boot" and item["level"] == "ok" for item in result["checks"])


def test_doctor_secure_boot_disabled_is_advisory_not_failure():
    result = diagnose(_scan(secure_boot=False))

    assert result["exit_code"] == 0
    assert any(item["id"] == "secure-boot" and item["level"] == "advisory" for item in result["checks"])


def test_doctor_windows_11_without_tpm_warns():
    result = diagnose(_scan(tpm_present=False, tpm_ready=False))

    assert result["exit_code"] == 1
    assert any(item["id"] == "tpm" and item["level"] == "warn" for item in result["checks"])


def test_doctor_registry_read_error_warns():
    data = _scan()
    data["registry"] = [{"error": "access denied"}]

    result = diagnose(data)

    assert result["exit_code"] == 1
    assert any(item["id"] == "registry-read" and item["level"] == "warn" for item in result["checks"])
