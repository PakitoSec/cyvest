"""
Tests for SharedInvestigationContext - thread-safe cross-task observable sharing.

This test module validates the SharedInvestigationContext feature that enables:
- Thread-safe parallel task execution
- Cross-task observable and check sharing
- Auto-reconcile pattern via context manager
- Deep copying for concurrent modification safety
- Manual and automatic reconciliation

Test coverage:
- Initialization and configuration inheritance
- Auto-reconcile on context manager exit
- Manual reconciliation
- Observable/check retrieval and lookup
- Thread-safe parallel execution
- Exception handling (auto-reconcile skipped on error)
- Deep copy semantics
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal

from cyvest import Cyvest, ObservableType, RelationshipType
from cyvest.investigation import Investigation, SharedInvestigationContext


def test_shared_context_initialization():
    """Test SharedInvestigationContext initialization."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    assert shared._main_investigation is inv
    assert shared._root_type == "artifact"
    assert len(shared._observable_registry) == 0
    assert len(shared._check_registry) == 0


def test_create_cyvest_inherits_config():
    """Test that create_cyvest inherits configuration from main investigation."""
    inv = Investigation({"email": "test@example.com"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        # Should inherit root_type
        assert cy.root().obs_type == ObservableType.ARTIFACT
        # Should inherit data
        assert cy.root().extra == {"email": "test@example.com"}


def test_auto_reconcile_on_context_exit():
    """Test that context manager auto-reconciles on successful exit."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.observable(ObservableType.EMAIL_ADDR, "user@domain.com")
        cy.check("email_check", "header", "Test check")

    # After exiting context, observable should be in registry
    assert "obs:email-addr:user@domain.com" in shared._observable_registry
    assert "chk:email_check:header" in shared._check_registry


def test_manual_reconcile():
    """Test manual reconciliation of investigation."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    # Create Cyvest without auto-reconcile
    cy = Cyvest({"test": "data"}, root_type="artifact")
    cy.observable(ObservableType.DOMAIN_NAME, "example.com")
    cy.check("domain_check", "network", "Test")

    # Manually reconcile
    shared.reconcile(cy)

    # Should be in registry
    assert "obs:domain-name:example.com" in shared._observable_registry
    assert "chk:domain_check:network" in shared._check_registry


def test_get_observable():
    """Test retrieving observable from shared context."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        original = cy.observable(ObservableType.IPV4_ADDR, "192.168.1.1")

    # Retrieve observable
    retrieved = shared.get_observable("obs:ipv4-addr:192.168.1.1")

    assert retrieved is not None
    assert retrieved.obs_type == ObservableType.IPV4_ADDR
    assert retrieved.value == "192.168.1.1"
    # Should be a deep copy, not the same object
    assert retrieved is not original.get()


def test_get_nonexistent_observable():
    """Test retrieving non-existent observable returns None."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    result = shared.get_observable("obs:ipv4-addr:10.0.0.1")
    assert result is None


def test_get_check():
    """Test retrieving check from shared context."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        original = cy.check("test_check", "scope", "Description")

    # Retrieve check
    retrieved = shared.get_check("chk:test_check:scope")

    assert retrieved is not None
    assert retrieved.check_id == "test_check"
    assert retrieved.scope == "scope"
    # Should be a deep copy
    assert retrieved is not original.get()


def test_has_observable():
    """Test checking if observable exists."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.observable(ObservableType.URL, "https://example.com")

    assert shared.has_observable("obs:url:https://example.com") is True
    assert shared.has_observable("obs:url:https://other.com") is False


def test_has_check():
    """Test checking if check exists."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.check("my_check", "category", "Description")

    assert shared.has_check("chk:my_check:category") is True
    assert shared.has_check("chk:other_check:category") is False


def test_list_observables():
    """Test listing all observable keys."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.observable(ObservableType.EMAIL_ADDR, "user1@example.com")
        cy.observable(ObservableType.EMAIL_ADDR, "user2@example.com")
        cy.observable(ObservableType.DOMAIN_NAME, "example.com")

    keys = shared.list_observables()
    assert len(keys) == 4  # 3 created + 1 root
    assert "obs:email-addr:user1@example.com" in keys
    assert "obs:email-addr:user2@example.com" in keys
    assert "obs:domain-name:example.com" in keys


def test_list_checks():
    """Test listing all check keys."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.check("check1", "scope1", "Description 1")
        cy.check("check2", "scope2", "Description 2")

    keys = shared.list_checks()
    assert len(keys) == 2
    assert "chk:check1:scope1" in keys
    assert "chk:check2:scope2" in keys


def test_find_observables_by_type():
    """Test finding observables by type."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.observable(ObservableType.EMAIL_ADDR, "user1@example.com")
        cy.observable(ObservableType.EMAIL_ADDR, "user2@example.com")
        cy.observable(ObservableType.DOMAIN_NAME, "example.com")
        cy.observable(ObservableType.IPV4_ADDR, "192.168.1.1")

    email_obs = shared.find_observables_by_type(ObservableType.EMAIL_ADDR)
    assert len(email_obs) == 2
    assert all(obs.obs_type == ObservableType.EMAIL_ADDR for obs in email_obs)

    domain_obs = shared.find_observables_by_type(ObservableType.DOMAIN_NAME)
    assert len(domain_obs) == 1
    assert domain_obs[0].value == "example.com"


def test_find_observables_by_value():
    """Test finding observables by value."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.observable(ObservableType.DOMAIN_NAME, "example.com")
        cy.observable(ObservableType.URL, "https://example.com/path")

    results = shared.find_observables_by_value("example.com")
    assert len(results) == 1
    assert results[0].obs_type == ObservableType.DOMAIN_NAME


def test_cross_task_observable_sharing():
    """Test that tasks can share observables across execution."""
    inv = Investigation({"domain": "malicious.com", "url": "https://malicious.com/payload"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    # Task 1: Create domain observable
    with shared.create_cyvest() as cy1:
        data = cy1.root().extra
        domain = cy1.observable(ObservableType.DOMAIN_NAME, data["domain"])
        domain.add_ti("VT", Decimal("8.0"))

    # Task 2: Reference domain from Task 1
    with shared.create_cyvest() as cy2:
        data = cy2.root().extra
        # Get shared domain
        domain = shared.get_observable("obs:domain-name:malicious.com")
        assert domain is not None
        assert domain.value == "malicious.com"

        # Create URL and link to shared domain
        url = cy2.observable(ObservableType.URL, data["url"])
        url.relate_to(domain, RelationshipType.RESOLVES_TO)

    # Verify final investigation has both observables
    final_inv = shared.get_investigation()
    assert "obs:domain-name:malicious.com" in final_inv._observables
    assert "obs:url:https://malicious.com/payload" in final_inv._observables


def test_thread_safety_parallel_tasks():
    """Test thread-safe execution of parallel tasks."""
    inv = Investigation(
        {"domains": ["domain1.com", "domain2.com", "domain3.com"], "ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]},
        root_type="artifact",
    )
    shared = SharedInvestigationContext(inv)

    def create_domain_observable(domain: str):
        """Task that creates a domain observable."""
        with shared.create_cyvest() as cy:
            cy.observable(ObservableType.DOMAIN_NAME, domain).add_ti("VT", Decimal("5.0"))

    def create_ip_observable(ip: str):
        """Task that creates an IP observable."""
        with shared.create_cyvest() as cy:
            cy.observable(ObservableType.IPV4_ADDR, ip).add_ti("SEKOIA", Decimal("3.0"))

    # Execute tasks in parallel
    with ThreadPoolExecutor(max_workers=6) as executor:
        data = inv._root_observable.extra
        futures = []

        # Submit domain tasks
        for domain in data["domains"]:
            futures.append(executor.submit(create_domain_observable, domain))

        # Submit IP tasks
        for ip in data["ips"]:
            futures.append(executor.submit(create_ip_observable, ip))

        # Wait for all to complete
        for future in as_completed(futures):
            future.result()

    # Verify all observables were registered (6 created + 1 root)
    assert len(shared.list_observables()) == 7
    assert shared.has_observable("obs:domain-name:domain1.com")
    assert shared.has_observable("obs:domain-name:domain2.com")
    assert shared.has_observable("obs:domain-name:domain3.com")
    assert shared.has_observable("obs:ipv4-addr:1.1.1.1")
    assert shared.has_observable("obs:ipv4-addr:2.2.2.2")
    assert shared.has_observable("obs:ipv4-addr:3.3.3.3")


def test_concurrent_reconciliation():
    """Test that concurrent reconciliation maintains data integrity."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    def create_check(check_id: str, category: str):
        """Task that creates a check."""
        with shared.create_cyvest() as cy:
            cy.check(check_id, category, f"Check {check_id}")

    # Create many checks concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for i in range(50):
            futures.append(executor.submit(create_check, f"check_{i}", f"cat_{i % 5}"))

        for future in as_completed(futures):
            future.result()

    # Verify all checks were registered
    assert len(shared.list_checks()) == 50


def test_get_investigation_returns_copy():
    """Test that get_investigation returns a proper copy."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.observable(ObservableType.EMAIL_ADDR, "test@example.com")

    inv_copy = shared.get_investigation()
    assert inv_copy is shared._main_investigation
    assert "obs:email-addr:test@example.com" in inv_copy._observables


def test_reconcile_with_investigation_object():
    """Test reconciling with Investigation object instead of Cyvest."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    # Create separate investigation
    other_inv = Investigation({"other": "data"}, root_type="artifact")
    cy = Cyvest({"other": "data"}, root_type="artifact")
    cy._investigation = other_inv

    obs = cy.observable(ObservableType.FILE, "malware.exe")
    obs.add_ti("VT", Decimal("10.0"))

    # Reconcile the investigation directly
    shared.reconcile(other_inv)

    # Should be in registry
    assert shared.has_observable("obs:file:malware.exe")


def test_auto_reconcile_on_exception_skipped():
    """Test that auto-reconcile is skipped if exception occurs in context."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    try:
        with shared.create_cyvest() as cy:
            cy.observable(ObservableType.EMAIL_ADDR, "fail@example.com")
            raise ValueError("Simulated error")
    except ValueError:
        pass

    # Observable should NOT be in registry due to exception
    assert not shared.has_observable("email-addr:fail@example.com")


def test_override_data_in_create_cyvest():
    """Test that data can be overridden in create_cyvest."""
    inv = Investigation({"original": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest(data={"override": "data"}) as cy:
        assert cy.root().extra == {"override": "data"}


def test_shared_context_with_checks_and_observables():
    """Test that both checks and observables are properly shared."""
    inv = Investigation(
        {"email": "phishing@malicious.com", "url": "https://malicious.com/payload"}, root_type="artifact"
    )
    shared = SharedInvestigationContext(inv)

    # Task 1: Analyze email
    with shared.create_cyvest() as cy:
        data = cy.root().extra
        email_obs = cy.observable(ObservableType.EMAIL_ADDR, data["email"])
        email_obs.add_ti("EmailRep", Decimal("7.0"))

        check = cy.check("email_analysis", "header", "Analyze sender")
        check.link_observable(email_obs.get())

    # Task 2: Analyze URL, reference email check
    with shared.create_cyvest() as cy:
        data = cy.root().extra
        url_obs = cy.observable(ObservableType.URL, data["url"])
        url_obs.add_ti("VT", Decimal("9.0"))

        # Verify we can see the email check
        email_check = shared.get_check("chk:email_analysis:header")
        assert email_check is not None
        assert email_check.check_id == "email_analysis"

        check = cy.check("url_analysis", "body", "Analyze malicious URL")
        check.link_observable(url_obs.get())

    # Verify final state
    assert len(shared.list_observables()) == 3  # 2 created + 1 root
    assert len(shared.list_checks()) == 2
    assert shared.has_observable("obs:email-addr:phishing@malicious.com")
    assert shared.has_observable("obs:url:https://malicious.com/payload")
    assert shared.has_check("chk:email_analysis:header")
    assert shared.has_check("chk:url_analysis:body")


def test_deep_copy_prevents_modification():
    """Test that deep copying prevents concurrent modification issues."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        obs = cy.observable(ObservableType.DOMAIN_NAME, "example.com")
        obs.add_ti("VT", Decimal("5.0"))

    # Get observable and modify it
    retrieved1 = shared.get_observable("obs:domain-name:example.com")
    retrieved1.value = "modified.com"  # Modify the copy

    # Get observable again - should be unchanged
    retrieved2 = shared.get_observable("obs:domain-name:example.com")
    assert retrieved2.value == "example.com"  # Original value preserved
    assert retrieved1 is not retrieved2  # Different objects
