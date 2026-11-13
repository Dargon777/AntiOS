from antios.document_inspection import inspect_document


def test_pdf_checks_names_but_ignores_comments_and_string_contents():
    data = b"%PDF-1.4\n% /Launch\n<< /Title (literal /JavaScript) /Raw <2f4a53> >>\n%%EOF\n"
    assert inspect_document(data, "file.bin").kind is None
    action = inspect_document(b"%PDF-1.4\n<< /S /JavaScript >>\n%%EOF", "file.pdf")
    assert action.kind == "review"
    assert action.rule_id == "pdf.active-content"


def test_pdf_encrypted_and_stream_content_is_not_marked_complete():
    data = b"%PDF-1.4\n<< /Encrypt 4 0 R >>\nstream\n /JavaScript\nendstream\n%%EOF"
    report = inspect_document(data, "file.pdf")
    assert report.kind is None and not report.complete
    assert report.coverage_gaps == {"encrypted-document", "pdf-stream-not-inspected"}


def test_pdf_direct_stream_boundary_resumes_dictionary_inspection():
    data = (
        b"%PDF-1.4\n<< /Length 4 >>\nstream\ntext\nendstream\n"
        b"<< /S /JavaScript >>\n%%EOF"
    )
    report = inspect_document(data, "file.pdf")
    assert report.rule_id == "pdf.active-content"
    assert report.coverage_gaps == {"pdf-stream-not-inspected"}


def test_rtf_distinguishes_object_controls_from_escaped_text():
    assert inspect_document(b"{\\rtf1 \\\\objdata}", "file.rtf").kind is None
    report = inspect_document(b"{\\rtf1{\\*\\objdata 0102}}", "file.bin")
    assert report.kind == "review" and not report.complete
    assert report.coverage_gaps == {"rtf-object-not-inspected"}


def test_truncated_rtf_and_ole_reports_have_explicit_gaps():
    rtf = inspect_document(b"{\\rtf1\\bin40 ab}", "file.rtf")
    assert rtf.coverage_gaps == {"rtf-binary-not-inspected", "invalid-rtf-structure"}
    ole = inspect_document(bytes.fromhex("d0cf11e0a1b11ae1") + bytes(504), "file.bin")
    assert ole.coverage_gaps == {"ole-streams-not-inspected"}


def test_svg_ignores_literal_text_and_rejects_dtd():
    harmless = b'<svg xmlns="http://www.w3.org/2000/svg"><text>&lt;script&gt;</text></svg>'
    assert inspect_document(harmless, "image.svg").complete
    assert inspect_document(harmless, "image.svg").kind is None
    active = b'<svg xmlns="http://www.w3.org/2000/svg" onload="/* inert */"/>'
    assert inspect_document(active, "image.svg").rule_id == "svg.active-content"
    dtd = b'<!DOCTYPE svg [<!ENTITY sample "inert">]><svg>&sample;</svg>'
    assert inspect_document(dtd, "image.svg").coverage_gaps == {"svg-doctype-not-inspected"}
