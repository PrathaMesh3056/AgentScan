from benchmarks.evaluation.dashboard import evaluate_dashboard


def test_dashboard_local_authenticated_scan_and_failure_are_distinct(tmp_path) -> None:
    rows = evaluate_dashboard(tmp_path)
    assert len(rows) == 3
    clean, inconclusive, failed = rows
    assert clean["dashboard_status"]["status"] == "completed"
    assert clean["dashboard_status"]["tests_run"] == 1
    assert failed["dashboard_status"]["status"] == "failed"
    assert failed["dashboard_status"]["score"] is None
    assert failed["dashboard_status"]["tests_run"] == 0
    assert failed["dashboard_status"]["module_errors"]
    assert inconclusive["dashboard_status"]["status"] == "inconclusive"
    assert inconclusive["dashboard_status"]["score"] is None
    assert inconclusive["dashboard_status"]["tests_run"] == 0
    assert inconclusive["dashboard_status"]["module_outcomes"][0]["status"] == "INCONCLUSIVE"
    for row in rows:
        assert set(row["exports"]) == {"json", "sarif", "html"}
        assert all(export["status"] == 200 for export in row["exports"].values())
        assert all(
            export["assessment_status"] == row["report_status"]
            for export in row["exports"].values()
        )
        assert all(export["coverage_verified"] for export in row["exports"].values())
        assert all(
            export["score_available"] is (row["report_status"] == "COMPLETE")
            for export in row["exports"].values()
        )
        assert all(
            "attachment" in export["content_disposition"] for export in row["exports"].values()
        )
