from antios.i18n import (
    LANGUAGE_NAMES,
    SUPPORTED_LANGUAGES,
    TRANSLATIONS,
    Translator,
    normalize_language,
)


def test_four_supported_languages_are_exposed():
    assert SUPPORTED_LANGUAGES == ("en", "ru", "es", "zh-CN")
    assert set(LANGUAGE_NAMES) == set(SUPPORTED_LANGUAGES)


def test_locale_normalization():
    assert normalize_language("en-US") == "en"
    assert normalize_language("ru-RU") == "ru"
    assert normalize_language("es-MX") == "es"
    assert normalize_language("zh_CN") == "zh-CN"
    assert normalize_language("fr-FR") == "en"


def test_all_languages_cover_the_english_catalog():
    english_keys = set(TRANSLATIONS["en"])
    for language in SUPPORTED_LANGUAGES:
        missing = english_keys - set(TRANSLATIONS[language])
        assert not missing, f"{language} is missing: {sorted(missing)}"


def test_translation_formats_dynamic_values():
    assert "12.5" in Translator("ru").t(
        "health.storage.ok",
        pct=12.5,
    )
    assert "7" in Translator("es").t(
        "health.startup.count",
        count=7,
    )
    assert "3" in Translator("zh-CN").t(
        "overview.completed",
        count=3,
    )


def test_unknown_key_falls_back_to_key_name():
    assert Translator("ru").t("missing.key") == "missing.key"
