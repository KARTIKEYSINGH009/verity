from verity.judge import (build_judge_prompt, judge_faithfulness,
                            parse_judge_response)


def test_judge_prompt_contains_context_and_answer():
    msgs = build_judge_prompt("ctx here", "answer here")
    assert msgs[0]["role"] == "system"
    assert "ctx here" in msgs[1]["content"]
    assert "answer here" in msgs[1]["content"]


def test_parse_valid_judge_json():
    raw = '{"score": 0.85, "verdict": "grounded", "rationale": "matches source"}'
    res = parse_judge_response(raw)
    assert res["score"] == 0.85
    assert res["verdict"] == "grounded"


def test_parse_judge_json_in_markdown_fence():
    raw = '```json\n{"score": 0.2, "verdict": "hallucination_risk", "rationale": "invented"}\n```'
    res = parse_judge_response(raw)
    assert res["verdict"] == "hallucination_risk"


def test_parse_garbage_falls_back_to_risk():
    res = parse_judge_response("not json at all")
    assert res["verdict"] == "hallucination_risk"
    assert res["score"] == 0.0


def test_parse_clamps_score_and_fixes_verdict():
    res = parse_judge_response('{"score": 9.9, "verdict": "bogus"}')
    assert res["score"] == 1.0
    assert res["verdict"] == "grounded"


def test_mock_mode_judge_falls_back_to_heuristic():
    # No API key in this environment -> mock path, never hits the network.
    res = judge_faithfulness(
        "Refunds are allowed within 30 days of purchase.",
        "You can return your purchase within 30 days.")
    assert res["verdict"] == "grounded"
    assert "mock" in res["method"]


def test_mock_mode_judge_flags_hallucination():
    res = judge_faithfulness(
        "Refunds are allowed within 30 days of purchase.",
        "The moon is made of cheese.")
    assert res["verdict"] == "hallucination_risk"
