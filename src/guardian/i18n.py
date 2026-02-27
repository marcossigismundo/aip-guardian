"""Internationalization support using Babel/gettext (English + Spanish)."""

from __future__ import annotations

import gettext
from pathlib import Path
from typing import Any

from starlette.requests import Request

LOCALE_DIR = Path(__file__).parent / "locale"
SUPPORTED_LANGUAGES = {"en": "English", "es": "Español"}
DEFAULT_LANGUAGE = "en"

_translations: dict[str, gettext.GNUTranslations | gettext.NullTranslations] = {}


def _load_translations() -> None:
    """Load .mo files for all supported languages."""
    for lang in SUPPORTED_LANGUAGES:
        try:
            _translations[lang] = gettext.translation(
                "messages",
                localedir=str(LOCALE_DIR),
                languages=[lang],
            )
        except FileNotFoundError:
            _translations[lang] = gettext.NullTranslations()


def get_locale(request: Request | None = None) -> str:
    """Determine user locale from cookie, header, or default."""
    if request is not None:
        # 1. Check cookie
        cookie_lang = request.cookies.get("guardian_lang")
        if cookie_lang in SUPPORTED_LANGUAGES:
            return cookie_lang

        # 2. Check Accept-Language header
        accept = request.headers.get("accept-language", "")
        for part in accept.split(","):
            lang = part.strip().split(";")[0].strip()[:2].lower()
            if lang in SUPPORTED_LANGUAGES:
                return lang

    return DEFAULT_LANGUAGE


def gettext_func(message: str, lang: str = DEFAULT_LANGUAGE) -> str:
    """Translate a message to the given language."""
    if not _translations:
        _load_translations()
    translator = _translations.get(lang, _translations.get(DEFAULT_LANGUAGE))
    if translator is None:
        return message
    return translator.gettext(message)


def ngettext_func(singular: str, plural: str, n: int, lang: str = DEFAULT_LANGUAGE) -> str:
    """Translate a plural message."""
    if not _translations:
        _load_translations()
    translator = _translations.get(lang, _translations.get(DEFAULT_LANGUAGE))
    if translator is None:
        return singular if n == 1 else plural
    return translator.ngettext(singular, plural, n)


def template_globals(request: Request | None = None) -> dict[str, Any]:
    """Return template context variables for i18n."""
    lang = get_locale(request)
    return {
        "_": lambda msg: gettext_func(msg, lang),
        "ngettext": lambda s, p, n: ngettext_func(s, p, n, lang),
        "current_lang": lang,
        "supported_languages": SUPPORTED_LANGUAGES,
    }
