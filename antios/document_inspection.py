"""Read-only inspection of common document metadata with explicit coverage gaps."""
from __future__ import annotations

import re
from xml.parsers import expat

from .engine_types import ScanOutcome


_DOCUMENT_LIMIT = 4 * 1024 * 1024
_OLE_HEADER = bytes.fromhex("d0cf11e0a1b11ae1")
_OLE_SUFFIXES = (".doc", ".dot", ".xls", ".xlt", ".ppt", ".pps", ".msi", ".msg")
_PDF_TOKENS = re.compile(rb"%[^\r\n]*|[()<>{}\[\]/]|[^%()<>{}\[\]/\x00\t\n\f\r ]+")
_PDF_NAME_ESCAPE = re.compile(rb"#([0-9a-fA-F]{2})")
_PDF_DELIMITERS = b"\x00\t\n\f\r %/()<>[]{}"
_PDF_INTEGER = re.compile(rb"[0-9]{1,10}\Z")
_RTF_WORD = re.compile(rb"([a-zA-Z]{1,32})(-?[0-9]{1,10})? ?")
_SVG_ROOT = re.compile(rb"<(?:[A-Za-z_][\w.-]*:)?svg(?=[\s/>])", re.ASCII)


def _outcome(gaps: set[str], *, rule: str = "", label: str = "", detail: str = "") -> ScanOutcome:
    return ScanOutcome(
        "review" if rule else None, label, complete=not gaps, detail=detail,
        rule_id=rule, coverage_gaps=frozenset(gaps),
    )


def _pdf_name(data: bytes, start: int) -> bytes:
    end = start
    while end < len(data) and data[end] not in _PDF_DELIMITERS and end - start < 128:
        end += 1
    return _PDF_NAME_ESCAPE.sub(lambda match: bytes([int(match[1], 16)]), data[start:end])


def _skip_literal(data: bytes, start: int) -> int:
    depth = 1
    index = start
    while index < len(data):
        char = data[index]
        index += 1
        if char == 92:  # An escaped parenthesis does not end the string.
            index += 1
        elif char == 40:
            depth += 1
        elif char == 41:
            depth -= 1
            if depth == 0:
                return index
    return len(data)


def _inspect_pdf(content: bytes) -> ScanOutcome:
    data = content[:_DOCUMENT_LIMIT]
    gaps = set()
    if len(content) > len(data):
        gaps.add("document-preview-only")
    if not data.startswith(b"%PDF-") or not content[-1024:].rstrip(b"\x00\t\n\f\r ").endswith(b"%%EOF"):
        gaps.add("invalid-pdf-structure")

    names = set()
    position = 0
    lengths = []
    stream_length = None
    while match := _PDF_TOKENS.search(data, position):
        token = match[0]
        position = match.end()
        if token == b"/":
            name = _pdf_name(data, position)
            if name in {b"JavaScript", b"JS", b"Launch", b"EmbeddedFile", b"EmbeddedFiles", b"ObjStm", b"Encrypt"}:
                names.add(name)
            # Skip the rest of the name so a name such as /stream cannot be
            # mistaken for a stream operator.
            value = _PDF_TOKENS.match(data, position)
            if value is not None and value[0][0] not in _PDF_DELIMITERS:
                position = value.end()
            if name == b"Length" and lengths:
                # Read the next lexical token only. An indirect reference
                # has more tokens before the dictionary ends.
                lengths[-1] = True
        elif token == b"(":
            position = _skip_literal(data, position)
        elif token == b"<":
            if data[position:position + 1] == b"<":
                position += 1
                lengths.append(None)
            else:
                end = data.find(b">", position)
                position = end + 1 if end >= 0 else len(data)
        elif token == b">" and data[position:position + 1] == b">" and lengths:
            position += 1
            stream_length = lengths.pop()
        elif token == b"stream":
            gaps.add("pdf-stream-not-inspected")
            if type(stream_length) is not int:
                break
            if data[position:position + 2] == b"\r\n":
                position += 2
            elif data[position:position + 1] == b"\n":
                position += 1
            else:
                break
            end = position + stream_length
            marker = _PDF_TOKENS.search(data, end) if end <= len(data) else None
            if marker is None or marker[0] != b"endstream" or data[end:marker.start()] not in (b"", b"\n", b"\r\n", b"\r"):
                break
            position = marker.end()
            stream_length = None
        elif lengths and lengths[-1] is True and _PDF_INTEGER.fullmatch(token):
            lengths[-1] = int(token)
        elif lengths and type(lengths[-1]) is int:
            lengths[-1] = None

    if b"ObjStm" in names:
        gaps.add("pdf-object-stream-not-inspected")
    if names & {b"EmbeddedFile", b"EmbeddedFiles"}:
        gaps.add("pdf-attachment-not-inspected")
    if b"Encrypt" in names:
        gaps.add("encrypted-document")
    if names & {b"JavaScript", b"JS", b"Launch"}:
        return _outcome(gaps, rule="pdf.active-content", label="PDF declares active content",
                        detail="PDF names reference JavaScript or an application launch")
    if "pdf-attachment-not-inspected" in gaps:
        return _outcome(gaps, rule="pdf.embedded-file", label="PDF declares embedded files",
                        detail="Embedded PDF file contents were not inspected")
    return _outcome(gaps, detail="PDF structure, encryption or streams limited inspection" if gaps else "")


def _inspect_rtf(content: bytes) -> ScanOutcome:
    data = content[:_DOCUMENT_LIMIT]
    gaps = set()
    if len(content) > len(data):
        gaps.add("document-preview-only")
    if not data.startswith(b"{\\rtf"):
        gaps.add("invalid-rtf-structure")
    depth = 0
    position = 0
    embedded = False
    while position < len(data):
        byte = data[position]
        position += 1
        if byte == 123:
            depth += 1
        elif byte == 125:
            depth -= 1
            if depth < 0:
                break
        elif byte == 92:
            word = _RTF_WORD.match(data, position)
            if word is None:
                position += 1
                continue
            position = word.end()
            if word[1] == b"bin":
                gaps.add("rtf-binary-not-inspected")
                length = int(word[2] or b"-1")
                if not 0 <= length <= len(data) - position:
                    gaps.add("invalid-rtf-structure")
                    break
                position += length
            elif word[1] in (b"objdata", b"objautlink", b"objupdate"):
                embedded = True
    if depth:
        gaps.add("invalid-rtf-structure")
    if embedded:
        gaps.add("rtf-object-not-inspected")
        return _outcome(gaps, rule="rtf.active-object", label="RTF declares embedded or linked content",
                        detail="RTF object contents or external links were not inspected")
    return _outcome(gaps, detail="RTF structure or binary content limited inspection" if gaps else "")


def _inspect_svg(content: bytes) -> ScanOutcome:
    active = False
    root_seen = False
    gaps = set()
    parser = expat.ParserCreate(namespace_separator=" ")

    def inspect_element(tag, attributes):
        nonlocal active, root_seen
        local = tag.rpartition(" ")[2]
        if not root_seen:
            root_seen = True
            if local != "svg":
                gaps.add("invalid-svg-root")
        if local in {"script", "foreignObject"} or any(
            key.rpartition(" ")[2].startswith("on") for key in attributes
        ):
            active = True

    def reject_doctype(*_):
        raise ValueError("SVG declares a DTD")

    parser.StartElementHandler = inspect_element
    parser.StartDoctypeDeclHandler = reject_doctype
    try:
        parser.Parse(content[:_DOCUMENT_LIMIT], len(content) <= _DOCUMENT_LIMIT)
    except expat.ExpatError:
        gaps.add("invalid-svg-structure")
    except ValueError:
        gaps.add("svg-doctype-not-inspected")
    if len(content) > _DOCUMENT_LIMIT:
        gaps.add("document-preview-only")
    if active:
        return _outcome(gaps, rule="svg.active-content", label="SVG declares active content",
                        detail="SVG declares a script, foreign object or event handler")
    return _outcome(gaps, detail="SVG structure or DTD limited inspection" if gaps else "")


def inspect_document(data: bytes, name: str) -> ScanOutcome:
    """Return advisory document observations without opening a viewer."""
    lower = name.lower()
    if data.startswith(b"%PDF-") or lower.endswith(".pdf"):
        return _inspect_pdf(data)
    if data.startswith(b"{\\rtf") or lower.endswith(".rtf"):
        return _inspect_rtf(data)
    if lower.endswith(".svg") or _SVG_ROOT.match(data[:512].lstrip()):
        return _inspect_svg(data)
    if lower.endswith(_OLE_SUFFIXES) or (len(data) >= 512 and data.startswith(_OLE_HEADER)):
        return _outcome(
            {"ole-streams-not-inspected"} if data.startswith(_OLE_HEADER) else {"invalid-ole-header"},
            detail="Legacy Office, Outlook or Windows Installer streams were not inspected",
        )
    return ScanOutcome()
