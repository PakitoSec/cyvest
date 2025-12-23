from cyvest import Cyvest
from cyvest.io_serialization import load_investigation_json
from cyvest.levels import Level
from cyvest.model import Container, Enrichment, Observable, ObservableType
from cyvest.score import ScoreMode


def test_serialization_preserves_root_type_and_score_mode_obs(tmp_path) -> None:
    cv = Cyvest(root_data={"source": "example"}, root_type=Cyvest.OBS.ARTIFACT, score_mode_obs=ScoreMode.SUM)

    path = tmp_path / "inv.json"
    cv.io_save_json(path)

    loaded = load_investigation_json(path)

    root = loaded.observable_get_root()
    assert root is not None
    assert root.obs_type == ObservableType.ARTIFACT
    assert loaded._investigation._score_engine._score_mode_obs == ScoreMode.SUM


def test_serialization_preserves_whitelisted_flag(tmp_path) -> None:
    cv = Cyvest()
    cv.investigation_add_whitelist("wl-1", "False positive", "FP justification")
    cv.investigation_add_whitelist("wl-2", "Second entry")

    path = tmp_path / "inv_whitelisted.json"
    cv.io_save_json(path)

    loaded = load_investigation_json(path)
    assert loaded.investigation_is_whitelisted() is True
    whitelists = loaded.investigation_get_whitelists()
    assert len(whitelists) == 2
    assert any(entry.identifier == "wl-1" and entry.justification == "FP justification" for entry in whitelists)


def test_markdown_excludes_containers_by_default() -> None:
    """Test that containers section is excluded by default in markdown report."""
    cv = Cyvest()

    # Add an observable
    obs = Observable(obs_type=ObservableType.DOMAIN_NAME, value="example.com", level=Level.INFO)
    cv._investigation.add_observable(obs)

    # Add a container
    container = Container(path="/test/container", description="Test container")
    cv._investigation.add_container(container)

    # Generate markdown without include_containers
    markdown = cv.io_to_markdown()

    # Verify containers section is not present
    assert "## Containers" not in markdown
    assert "/test/container" not in markdown


def test_markdown_includes_containers_when_enabled() -> None:
    """Test that containers section is included when include_containers=True."""
    cv = Cyvest()

    # Add an observable
    obs = Observable(obs_type=ObservableType.DOMAIN_NAME, value="example.com", level=Level.INFO)
    cv._investigation.add_observable(obs)

    # Add a container
    container = Container(path="/test/container", description="Test container")
    cv._investigation.add_container(container)

    # Generate markdown with include_containers=True
    markdown = cv.io_to_markdown(include_containers=True)

    # Verify containers section is present
    assert "## Containers" in markdown
    assert "/test/container" in markdown
    assert "Test container" in markdown


def test_markdown_excludes_enrichments_by_default() -> None:
    """Test that enrichments section is excluded by default in markdown report."""
    cv = Cyvest()

    # Add an observable
    obs = Observable(obs_type=ObservableType.DOMAIN_NAME, value="example.com", level=Level.INFO)
    cv._investigation.add_observable(obs)

    # Add an enrichment
    enrichment = Enrichment(name="TestEnrichment", data={"key": "value"}, context="test context")
    cv._investigation.add_enrichment(enrichment)

    # Generate markdown without include_enrichments
    markdown = cv.io_to_markdown()

    # Verify enrichments section is not present
    assert "## Enrichments" not in markdown
    assert "TestEnrichment" not in markdown


def test_markdown_includes_enrichments_when_enabled() -> None:
    """Test that enrichments section is included when include_enrichments=True."""
    cv = Cyvest()

    # Add an observable
    obs = Observable(obs_type=ObservableType.DOMAIN_NAME, value="example.com", level=Level.INFO)
    cv._investigation.add_observable(obs)

    # Add an enrichment
    enrichment = Enrichment(name="TestEnrichment", data={"key": "value"}, context="test context")
    cv._investigation.add_enrichment(enrichment)

    # Generate markdown with include_enrichments=True
    markdown = cv.io_to_markdown(include_enrichments=True)

    # Verify enrichments section is present
    assert "## Enrichments" in markdown
    assert "TestEnrichment" in markdown
    assert "test context" in markdown


def test_markdown_includes_observables_by_default() -> None:
    """Test that observables section is included by default in markdown report."""
    cv = Cyvest()

    obs = Observable(obs_type=ObservableType.DOMAIN_NAME, value="example.com", level=Level.INFO)
    cv._investigation.add_observable(obs)

    markdown = cv.io_to_markdown()

    assert "## Observables" in markdown
    assert "example.com" in markdown


def test_markdown_excludes_observables_when_disabled() -> None:
    """Test that observables section is excluded when include_observables=False."""
    cv = Cyvest()

    obs = Observable(obs_type=ObservableType.DOMAIN_NAME, value="example.com", level=Level.INFO)
    cv._investigation.add_observable(obs)

    markdown = cv.io_to_markdown(include_observables=False)

    assert "## Observables" not in markdown
    assert "example.com" not in markdown


def test_markdown_removes_observables_by_type_and_level_section() -> None:
    """Test that 'Observables by Type and Level' section is removed from markdown report."""
    cv = Cyvest()

    # Add observables with different types and levels
    obs1 = Observable(obs_type=ObservableType.DOMAIN_NAME, value="example.com", level=Level.INFO)
    obs2 = Observable(obs_type=ObservableType.IPV4_ADDR, value="192.168.1.1", level=Level.SUSPICIOUS)
    cv._investigation.add_observable(obs1)
    cv._investigation.add_observable(obs2)

    # Generate markdown
    markdown = cv.io_to_markdown()

    # Verify the section is not present
    assert "Observables by Type and Level" not in markdown
    assert "### Observables by Type and Level" not in markdown


def test_markdown_wrapper_methods_support_optional_parameters() -> None:
    """Test that Cyvest wrapper methods support optional parameters."""
    cv = Cyvest()

    # Add observable, container, and enrichment
    obs = Observable(obs_type=ObservableType.DOMAIN_NAME, value="example.com", level=Level.INFO)
    cv._investigation.add_observable(obs)

    container = Container(path="/test", description="Test")
    cv._investigation.add_container(container)

    enrichment = Enrichment(name="Test", data={})
    cv._investigation.add_enrichment(enrichment)

    # Test default behavior (excludes both)
    markdown_default = cv.io_to_markdown()
    assert "## Observables" in markdown_default
    assert "## Containers" not in markdown_default
    assert "## Enrichments" not in markdown_default

    # Test with containers enabled
    markdown_containers = cv.io_to_markdown(include_containers=True)
    assert "## Containers" in markdown_containers
    assert "## Enrichments" not in markdown_containers

    # Test with enrichments enabled
    markdown_enrichments = cv.io_to_markdown(include_enrichments=True)
    assert "## Containers" not in markdown_enrichments
    assert "## Enrichments" in markdown_enrichments

    # Test with both enabled
    markdown_both = cv.io_to_markdown(include_containers=True, include_enrichments=True)
    assert "## Containers" in markdown_both
    assert "## Enrichments" in markdown_both

    # Test with observables disabled
    markdown_no_observables = cv.io_to_markdown(include_observables=False)
    assert "## Observables" not in markdown_no_observables
    assert "example.com" not in markdown_no_observables
