"""The report's link to a reference page and the path a bundle files it under are one path."""

from mcp_kymograph import evidence, report, signals


def test_the_report_links_the_path_the_bundle_files_a_page_under():
    assert not hasattr(report, "REFERENCE_DIR"), "one constant, evidence's"
    for signal in signals.Signal:
        assert report.reference_page(signal.value) == f"{evidence.REFERENCE_DIR}/{signal.value}.md"
