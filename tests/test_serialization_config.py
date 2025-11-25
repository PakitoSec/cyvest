from cyvest import Cyvest
from cyvest.io_serialization import load_investigation_json, save_investigation_json
from cyvest.model import ObservableType
from cyvest.score import ScoreMode


def test_serialization_preserves_root_type_and_score_mode(tmp_path) -> None:
    cv = Cyvest(data={"source": "example"}, root_type="artifact", score_mode=ScoreMode.SUM)

    path = tmp_path / "inv.json"
    save_investigation_json(cv, path)

    loaded = load_investigation_json(path)

    root = loaded.observable_get_root()
    assert root is not None
    assert root.obs_type == ObservableType.ARTIFACT
    assert loaded._investigation._score_engine._score_mode == ScoreMode.SUM


def test_serialization_preserves_whitelisted_flag(tmp_path) -> None:
    cv = Cyvest()
    cv.investigation_set_whitelisted(True)

    path = tmp_path / "inv_whitelisted.json"
    save_investigation_json(cv, path)

    loaded = load_investigation_json(path)
    assert loaded.investigation_is_whitelisted() is True
