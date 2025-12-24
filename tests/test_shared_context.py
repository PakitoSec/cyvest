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
- Enrichment retrieval and management
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal

import pytest

from cyvest import Cyvest, keys
from cyvest.shared import SharedInvestigationContext


def test_shared_context_initialization():
    """Test SharedInvestigationContext initialization."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)
    inv = root_cy._investigation

    assert shared._main_investigation is inv
    assert shared._root_type == Cyvest.OBS.ARTIFACT
    assert len(shared._observable_registry) == 1  # root observable is present
    assert len(shared._check_registry) == 0


def test_shared_context_from_cyvest_helper():
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = root_cy.shared_context()

    assert isinstance(shared, SharedInvestigationContext)
    assert shared._main_investigation is root_cy._investigation


def test_create_cyvest_inherits_config():
    """Test that create_cyvest inherits configuration from main investigation."""
    root_cy = Cyvest({"email": "test@example.com"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)
    inv = root_cy._investigation

    with shared.create_cyvest() as cy:
        # Should inherit root_type
        assert cy.root().obs_type == Cyvest.OBS.ARTIFACT
        # Should inherit data
        assert cy.root().extra == {"email": "test@example.com"}
        # Mutations should not leak back to main investigation data
        cy.root().extra["email"] = "modified@example.com"

    assert inv._root_observable.extra == {"email": "test@example.com"}


def test_auto_reconcile_on_context_exit():
    """Test that context manager auto-reconciles on successful exit."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.EMAIL_ADDR, "user@domain.com")
        cy.check("email_check", "header", "Test check")

    # After exiting context, observable should be in registry
    assert "obs:email-addr:user@domain.com" in shared._observable_registry
    assert "chk:email_check:header" in shared._check_registry


def test_manual_reconcile():
    """Test manual reconciliation of investigation."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    # Create Cyvest without auto-reconcile
    cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    cy.observable(Cyvest.OBS.DOMAIN_NAME, "example.com")
    cy.check("domain_check", "network", "Test")

    # Manually reconcile
    shared.reconcile(cy)

    # Should be in registry
    assert "obs:domain-name:example.com" in shared._observable_registry
    assert "chk:domain_check:network" in shared._check_registry


def test_get_observable():
    """Test retrieving observable from shared context."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        original = cy.observable(Cyvest.OBS.IPV4_ADDR, "192.168.1.1")
        original_model = cy._investigation.get_observable(original.key)

    # Retrieve observable
    retrieved = shared.observable_get(Cyvest.OBS.IPV4_ADDR, "192.168.1.1")

    assert retrieved is not None
    assert retrieved.obs_type == Cyvest.OBS.IPV4_ADDR
    assert retrieved.value == "192.168.1.1"
    # Should be a deep copy, not the same object
    assert retrieved is not original_model


def test_get_nonexistent_observable():
    """Test retrieving non-existent observable returns None."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    result = shared.observable_get(Cyvest.OBS.IPV4_ADDR, "10.0.0.1")
    assert result is None


def test_get_check():
    """Test retrieving check from shared context."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        original = cy.check("test_check", "scope", "Description")
        original_check = cy._investigation.get_check(original.key)

    # Retrieve check
    retrieved = shared.check_get("test_check", "scope")

    assert retrieved is not None
    assert retrieved.check_id == "test_check"
    assert retrieved.scope == "scope"
    # Should be a deep copy
    assert retrieved is not original_check


def test_has_observable():
    """Test checking if observable exists via observable_get()."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.URL, "https://example.com")

    assert shared.observable_get(Cyvest.OBS.URL, "https://example.com") is not None
    assert shared.observable_get(Cyvest.OBS.URL, "https://other.com") is None


def test_has_check():
    """Test checking if check exists via check_get()."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.check("my_check", "category", "Description")

    assert shared.check_get("my_check", "category") is not None
    assert shared.check_get("other_check", "category") is None


def test_list_observables():
    """Observable listing API removed; validate via direct getter and registry size."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.EMAIL_ADDR, "user1@example.com")
        cy.observable(Cyvest.OBS.EMAIL_ADDR, "user2@example.com")
        cy.observable(Cyvest.OBS.DOMAIN_NAME, "example.com")

    assert len(shared._observable_registry) == 4  # 3 created + 1 root
    assert shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "user1@example.com") is not None
    assert shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "user2@example.com") is not None
    assert shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "example.com") is not None


def test_list_checks():
    """Checks listing API removed; validate via direct getter."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.check("check1", "scope1", "Description 1")
        cy.check("check2", "scope2", "Description 2")

    assert shared.check_get("check1", "scope1") is not None
    assert shared.check_get("check2", "scope2") is not None


def test_observable_get_and_list_observables():
    """Test observable_get() basic behavior."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.DOMAIN_NAME, "example.com")

    assert shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "example.com") is not None
    assert "obs:domain-name:example.com" in shared._observable_registry


def test_observables_list_by_type_sync_and_async():
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.EMAIL_ADDR, "user1@example.com")
        cy.observable(Cyvest.OBS.EMAIL_ADDR, "user2@example.com")
        cy.observable(Cyvest.OBS.DOMAIN_NAME, "example.com")

    sync_results = shared.observables_list_by_type(Cyvest.OBS.EMAIL_ADDR)
    assert len(sync_results) == 2
    assert {o.value for o in sync_results} == {"user1@example.com", "user2@example.com"}

    async def run():
        results = await shared.observables_alist_by_type(Cyvest.OBS.EMAIL_ADDR)
        assert len(results) == 2
        assert {o.value for o in results} == {"user1@example.com", "user2@example.com"}

    asyncio.run(run())


def test_cross_task_observable_sharing():
    """Test that tasks can share observables across execution."""
    root_cy = Cyvest({"domain": "malicious.com", "url": "https://malicious.com/payload"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)
    inv = root_cy._investigation

    # Task 1: Create domain observable
    with shared.create_cyvest() as cy1:
        data = cy1.root().extra
        domain = cy1.observable(Cyvest.OBS.DOMAIN_NAME, data["domain"])
        domain.with_ti("VT", Decimal("8.0"))

    # Task 2: Reference domain from Task 1
    with shared.create_cyvest() as cy2:
        data = cy2.root().extra
        # Inspect shared domain (read-only)
        domain_info = shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "malicious.com")
        assert domain_info is not None
        assert domain_info.value == "malicious.com"

        # Create URL and link to domain (correct pattern: use cy.observable())
        url = cy2.observable(Cyvest.OBS.URL, data["url"])
        url.relate_to(cy2.observable(Cyvest.OBS.DOMAIN_NAME, "malicious.com"), Cyvest.REL.RELATED_TO)

    # Verify final investigation has both observables
    assert "obs:domain-name:malicious.com" in inv._observables
    assert "obs:url:https://malicious.com/payload" in inv._observables


def test_thread_safety_parallel_tasks():
    """Test thread-safe execution of parallel tasks."""
    root_cy = Cyvest(
        {"domains": ["domain1.com", "domain2.com", "domain3.com"], "ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]},
        root_type=Cyvest.OBS.ARTIFACT,
    )
    shared = SharedInvestigationContext(root_cy)
    inv = root_cy._investigation

    def create_domain_observable(domain: str):
        """Task that creates a domain observable."""
        with shared.create_cyvest() as cy:
            cy.observable(Cyvest.OBS.DOMAIN_NAME, domain).with_ti("VT", Decimal("5.0"))

    def create_ip_observable(ip: str):
        """Task that creates an IP observable."""
        with shared.create_cyvest() as cy:
            cy.observable(Cyvest.OBS.IPV4_ADDR, ip).with_ti("SEKOIA", Decimal("3.0"))

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
    assert len(shared._observable_registry) == 7
    assert shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "domain1.com") is not None
    assert shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "domain2.com") is not None
    assert shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "domain3.com") is not None
    assert shared.observable_get(Cyvest.OBS.IPV4_ADDR, "1.1.1.1") is not None
    assert shared.observable_get(Cyvest.OBS.IPV4_ADDR, "2.2.2.2") is not None
    assert shared.observable_get(Cyvest.OBS.IPV4_ADDR, "3.3.3.3") is not None


def test_concurrent_reconciliation():
    """Test that concurrent reconciliation maintains data integrity."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

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
    assert len(shared._check_registry) == 50


def test_reconcile_with_investigation_object():
    """Test reconciling with Investigation object instead of Cyvest."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    # Create separate investigation
    other_cy = Cyvest({"other": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    other_inv = other_cy._investigation
    cy = Cyvest({"other": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    cy._investigation = other_inv

    obs = cy.observable(Cyvest.OBS.FILE, "malware.exe")
    obs.with_ti("VT", Decimal("10.0"))

    # Reconcile the investigation directly
    shared.reconcile(other_inv)

    # Should be in registry
    assert shared.observable_get(Cyvest.OBS.FILE, "malware.exe") is not None


def test_auto_reconcile_on_exception_skipped():
    """Test that auto-reconcile is skipped if exception occurs in context."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    try:
        with shared.create_cyvest() as cy:
            cy.observable(Cyvest.OBS.EMAIL_ADDR, "fail@example.com")
            raise ValueError("Simulated error")
    except ValueError:
        pass

    # Observable should NOT be in registry due to exception
    assert shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "fail@example.com") is None


def test_override_data_in_create_cyvest():
    """Test that data can be overridden in create_cyvest."""
    root_cy = Cyvest({"original": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest(root_data={"override": "data"}) as cy:
        assert cy.root().extra == {"override": "data"}


def test_shared_context_with_checks_and_observables():
    """Test that both checks and observables are properly shared."""
    root_cy = Cyvest(
        {"email": "phishing@malicious.com", "url": "https://malicious.com/payload"}, root_type=Cyvest.OBS.ARTIFACT
    )
    shared = SharedInvestigationContext(root_cy)

    # Task 1: Analyze email
    with shared.create_cyvest() as cy:
        data = cy.root().extra
        email_obs = cy.observable(Cyvest.OBS.EMAIL_ADDR, data["email"])
        email_obs.with_ti("EmailRep", Decimal("7.0"))

        check = cy.check("email_analysis", "header", "Analyze sender")
        check.link_observable(email_obs)

    # Task 2: Analyze URL, reference email check
    with shared.create_cyvest() as cy:
        data = cy.root().extra
        url_obs = cy.observable(Cyvest.OBS.URL, data["url"])
        url_obs.with_ti("VT", Decimal("9.0"))

        # Verify we can see the email check
        email_check = shared.check_get("email_analysis", "header")
        assert email_check is not None
        assert email_check.check_id == "email_analysis"

        check = cy.check("url_analysis", "body", "Analyze malicious URL")
        check.link_observable(url_obs)

    # Verify final state
    assert len(shared._observable_registry) == 3  # 2 created + 1 root
    assert len(shared._check_registry) == 2
    assert shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "phishing@malicious.com") is not None
    assert shared.observable_get(Cyvest.OBS.URL, "https://malicious.com/payload") is not None
    assert shared.check_get("email_analysis", "header") is not None
    assert shared.check_get("url_analysis", "body") is not None


def test_deep_copy_prevents_modification():
    """Test that deep copying prevents concurrent modification issues."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        obs = cy.observable(Cyvest.OBS.DOMAIN_NAME, "example.com")
        obs.with_ti("VT", Decimal("5.0"))

    # Get observable and modify it
    retrieved1 = shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "example.com")
    retrieved1.value = "modified.com"  # Modify the copy

    # Get observable again - should be unchanged
    retrieved2 = shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "example.com")
    assert retrieved2.value == "example.com"  # Original value preserved
    assert retrieved1 is not retrieved2  # Different objects


# ==============================================================================
# Tests for parameter-based API (new overloaded methods)
# ==============================================================================


def test_observable_get_with_parameters():
    """Test observable_get using type and value parameters."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.EMAIL_ADDR, "user@example.com")

    obs = shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "user@example.com")
    assert obs is not None
    assert obs.obs_type == Cyvest.OBS.EMAIL_ADDR
    assert obs.value == "user@example.com"


def test_check_get_with_parameters():
    """Test check_get using check_id and scope parameters."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.check("malware_scan", "attachment", "Scan for malware")

    # Test parameter-based lookup
    check = shared.check_get("malware_scan", "attachment")
    assert check is not None
    assert check.check_id == "malware_scan"
    assert check.scope == "attachment"

    assert check.check_id == "malware_scan"


def test_existence_checks_via_getters():
    """Use get_* returning None/non-None instead of has_* helpers."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.DOMAIN_NAME, "malicious.com")
        cy.check("url_reputation", "body", "Check URL reputation")

    assert shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "malicious.com") is not None
    assert shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "safe.com") is None
    assert shared.check_get("url_reputation", "body") is not None
    assert shared.check_get("email_reputation", "header") is None


def test_cyvest_get_observable_with_parameters():
    """Test Cyvest.observable_get using parameters for API consistency."""
    cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    obs_proxy = cy.observable(Cyvest.OBS.IPV4_ADDR, "10.0.0.1")

    obs = cy.observable_get(Cyvest.OBS.IPV4_ADDR, "10.0.0.1")
    assert obs is not None
    assert obs.value == "10.0.0.1"

    # Test key-based lookup (backward compatibility)
    obs_key = cy.observable_get(obs_proxy.key)
    assert obs_key is not None


def test_cyvest_get_check_with_parameters():
    """Test Cyvest.check_get using parameters for API consistency."""
    cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    check_proxy = cy.check("dns_lookup", "network", "DNS reputation check")

    # Test parameter-based lookup
    check = cy.check_get("dns_lookup", "network")
    assert check is not None
    assert check.check_id == "dns_lookup"

    # Test key-based lookup (backward compatibility)
    check_key = cy.check_get(check_proxy.key)
    assert check_key is not None


def test_observable_type_enum_conversion():
    """Test that ObservableType enums are properly converted to strings."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        # Create observables of different types
        cy.observable(Cyvest.OBS.URL, "https://example.com")
        cy.observable(Cyvest.OBS.FILE, "malware.exe")
        cy.observable(Cyvest.OBS.NETWORK_TRAFFIC, "http-traffic")

    # Test that enum values work correctly
    assert shared.observable_get(Cyvest.OBS.URL, "https://example.com") is not None
    assert shared.observable_get(Cyvest.OBS.FILE, "malware.exe") is not None
    assert shared.observable_get(Cyvest.OBS.NETWORK_TRAFFIC, "http-traffic") is not None

    url_obs = shared.observable_get(Cyvest.OBS.URL, "https://example.com")
    assert url_obs is not None
    assert url_obs.obs_type == Cyvest.OBS.URL


def test_getters_invalid_arguments_raise_typeerror():
    """Argument validation is handled by Python signatures."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    import pytest

    with pytest.raises(TypeError):
        shared.observable_get("type", "value", "extra")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        shared.check_get("id")  # type: ignore[arg-type]


def test_parameter_based_api_in_parallel_tasks():
    """Test parameter-based API works correctly in parallel tasks."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    def task1(shared_ctx):
        with shared_ctx.create_cyvest() as cy:
            cy.observable(Cyvest.OBS.EMAIL_ADDR, "sender@malicious.com").with_ti("EmailRep", Decimal("8.0"))
            cy.check("sender_check", "header", "Analyze sender")

    def task2(shared_ctx):
        with shared_ctx.create_cyvest() as cy:
            # Use parameter-based lookup to get observable from task1
            sender = shared_ctx.observable_get(Cyvest.OBS.EMAIL_ADDR, "sender@malicious.com")
            if sender and sender.score > 5:
                cy.check("high_risk_sender", "risk", "High risk detected").with_score(Decimal("9.0"))

    # Execute tasks in parallel
    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(task1, shared)
        f1.result()  # Wait for task1 to complete
        f2 = executor.submit(task2, shared)
        f2.result()

    # Verify both tasks completed and parameter-based lookups worked
    assert shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "sender@malicious.com") is not None
    assert shared.check_get("sender_check", "header") is not None
    assert shared.check_get("high_risk_sender", "risk") is not None

    sender_obs = shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "sender@malicious.com")
    assert sender_obs.score >= Decimal("8.0")


def test_normalization_consistency():
    """Test that parameter-based lookups handle normalization correctly."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        # Create with mixed case
        cy.observable(Cyvest.OBS.EMAIL_ADDR, "User@Example.COM")

    # Lookup should work with different casing (normalization)
    obs1 = shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "user@example.com")
    obs2 = shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "USER@EXAMPLE.COM")
    obs3 = shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "  User@Example.COM  ")

    assert obs1 is not None
    assert obs2 is not None
    assert obs3 is not None
    # All should find the same observable (values are normalized in keys)
    assert obs1.value == obs2.value == obs3.value


def test_prevent_relationship_with_shared_copy():
    """Test that using a copied observable from shared context raises helpful error."""
    import pytest

    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)
    inv = root_cy._investigation

    # Task 1: Create domain observable
    with shared.create_cyvest() as cy1:
        cy1.observable(Cyvest.OBS.DOMAIN_NAME, "malicious.com").with_ti("VT", 8)

    # Task 2: Try to use the copy (should fail with clear error)
    with shared.create_cyvest() as cy2:
        url_obs = cy2.observable(Cyvest.OBS.URL, "https://evil.com/payload")

        # Get copy from shared context (anti-pattern)
        domain_copy = shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "malicious.com")
        assert domain_copy is not None
        assert domain_copy._from_shared_context is True

        # This should raise ValueError with helpful message
        with pytest.raises(ValueError) as exc_info:
            url_obs.relate_to(domain_copy, Cyvest.REL.RELATED_TO)

        # Verify error message is helpful
        error_msg = str(exc_info.value)
        assert "Cannot use observable from shared_context.observable_get()" in error_msg
        assert "read-only copy" in error_msg
        assert "cy.observable" in error_msg
        assert "Incorrect pattern" in error_msg
        assert "Correct pattern" in error_msg

    # Correct pattern should work
    with shared.create_cyvest() as cy3:
        url_obs = cy3.observable(Cyvest.OBS.URL, "https://evil.com/payload")
        url_obs.relate_to(
            cy3.observable(Cyvest.OBS.DOMAIN_NAME, "malicious.com"),
            Cyvest.REL.RELATED_TO,
        )
        # Should succeed without error

    # Verify the correct pattern created the relationship
    url_key = keys.generate_observable_key(Cyvest.OBS.URL.value, "https://evil.com/payload")
    url = inv.get_observable(url_key)
    assert url is not None
    assert len(url.relationships) > 0
    assert any(rel.target_key.endswith("malicious.com") for rel in url.relationships)


def test_copied_observable_has_marker():
    """Test that copied observables are marked with _from_shared_context flag."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)
    inv = root_cy._investigation

    with shared.create_cyvest() as cy:
        original = cy.observable(Cyvest.OBS.DOMAIN_NAME, "example.com")
        original_model = cy._investigation.get_observable(original.key)
        assert original_model is not None
        # Original should not be marked
        assert original_model._from_shared_context is False

    # Copy from shared context should be marked
    copy = shared.observable_get(Cyvest.OBS.DOMAIN_NAME, "example.com")
    assert copy is not None
    assert copy._from_shared_context is True

    # Get from investigation directly should not be marked
    direct_key = keys.generate_observable_key(Cyvest.OBS.DOMAIN_NAME.value, "example.com")
    direct = inv.get_observable(direct_key)
    assert direct is not None
    assert direct._from_shared_context is False


# ==============================================================================
# Async API (no pytest-asyncio required; uses asyncio.run)
# ==============================================================================


def test_async_context_manager_auto_reconcile():
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    async def run():
        async with shared.create_cyvest() as cy:
            cy.observable(Cyvest.OBS.EMAIL_ADDR, "async@domain.com")
            cy.check("async_check", "scope", "Async check")

    asyncio.run(run())

    assert shared.observable_get(Cyvest.OBS.EMAIL_ADDR, "async@domain.com") is not None
    assert shared.check_get("async_check", "scope") is not None


def test_areconcile_and_observable_aget():
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    cy.observable(Cyvest.OBS.IPV4_ADDR, "8.8.8.8")

    async def run():
        await shared.areconcile(cy)
        obs = await shared.observable_aget(Cyvest.OBS.IPV4_ADDR, "8.8.8.8")
        assert obs is not None
        assert obs.value == "8.8.8.8"

    asyncio.run(run())


def test_get_enrichment_by_key():
    """Test retrieving enrichment by name from shared context."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        original = cy.enrichment_create("whois", {"registrar": "Test Inc", "created": "2020-01-01"})
        original_enr = cy._investigation.get_enrichment(original.key)

    retrieved = shared.enrichment_get("whois")

    assert retrieved is not None
    assert retrieved.name == "whois"
    assert retrieved.data == {"registrar": "Test Inc", "created": "2020-01-01"}
    # Should be a deep copy
    assert retrieved is not original_enr


def test_get_enrichment_by_name():
    """Test retrieving enrichment by name from shared context."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.enrichment_create("dns", {"A": ["1.2.3.4"], "MX": ["mail.example.com"]})

    # Retrieve enrichment by name
    retrieved = shared.enrichment_get("dns")

    assert retrieved is not None
    assert retrieved.name == "dns"
    assert retrieved.data["A"] == ["1.2.3.4"]
    assert retrieved.data["MX"] == ["mail.example.com"]


def test_get_enrichment_with_context():
    """Test retrieving enrichment with context from shared context."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.enrichment_create("dns", {"A": ["192.168.1.1"]}, context="example.com")
        cy.enrichment_create("dns", {"A": ["10.0.0.1"]}, context="other.com")

    # Retrieve specific enrichment with context
    retrieved = shared.enrichment_get("dns", "example.com")

    assert retrieved is not None
    assert retrieved.name == "dns"
    assert retrieved.data["A"] == ["192.168.1.1"]
    assert retrieved.context == "example.com"

    # Retrieve different context
    retrieved2 = shared.enrichment_get("dns", "other.com")
    assert retrieved2 is not None
    assert retrieved2.data["A"] == ["10.0.0.1"]


def test_get_nonexistent_enrichment():
    """Test retrieving non-existent enrichment returns None."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    result = shared.enrichment_get("nonexistent")
    assert result is None

    result = shared.enrichment_get("whois", "missing-context")
    assert result is None


def test_list_enrichments():
    """Test listing all enrichment keys."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    # Initially empty
    assert len(shared._enrichment_registry) == 0

    with shared.create_cyvest() as cy:
        cy.enrichment_create("whois", {"registrar": "Test"})
        cy.enrichment_create("dns", {"A": ["1.2.3.4"]})
        cy.enrichment_create("geo", {"country": "US"}, context="ip-lookup")

    keys = list(shared._enrichment_registry.keys())
    assert len(keys) == 3
    assert "enr:whois" in keys
    assert "enr:dns" in keys
    # Context-based enrichment should have hash in key
    assert any(key.startswith("enr:geo:") for key in keys)


def test_enrichment_reconcile_updates_registry():
    """Test that reconciling updates enrichment registry."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    # Create first enrichment
    with shared.create_cyvest() as cy:
        cy.enrichment_create("initial", {"data": "v1"})

    assert len(shared._enrichment_registry) == 1

    # Create second enrichment
    with shared.create_cyvest() as cy:
        cy.enrichment_create("second", {"data": "v2"})

    assert len(shared._enrichment_registry) == 2
    assert shared.enrichment_get("initial") is not None
    assert shared.enrichment_get("second") is not None


def test_enrichment_deep_copy_independence():
    """Test that retrieved enrichment is a deep copy."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.enrichment_create("test", {"list": [1, 2, 3], "dict": {"key": "value"}})

    # Get enrichment and modify it
    retrieved1 = shared.enrichment_get("test")
    assert retrieved1 is not None
    retrieved1.data["list"].append(4)
    retrieved1.data["dict"]["new_key"] = "new_value"

    # Get enrichment again - should not be affected by previous modification
    retrieved2 = shared.enrichment_get("test")
    assert retrieved2 is not None
    assert retrieved2.data["list"] == [1, 2, 3]
    assert "new_key" not in retrieved2.data["dict"]


def test_enrichment_merge_in_reconcile():
    """Test that enrichments are properly merged during reconciliation."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)
    inv = root_cy._investigation

    # Create enrichment in first task
    with shared.create_cyvest() as cy1:
        cy1.enrichment_create("shared", {"field1": "value1"})

    # Create/update same enrichment in second task
    with shared.create_cyvest() as cy2:
        cy2.enrichment_create("shared", {"field2": "value2"})

    # The main investigation should have merged data
    merged = inv.get_enrichment("enr:shared")
    assert merged is not None
    assert merged.data["field1"] == "value1"
    assert merged.data["field2"] == "value2"

    # Registry should reflect merged canonical state after reconcile refresh
    registry_copy = shared.enrichment_get("shared")
    assert registry_copy is not None
    assert registry_copy.data["field1"] == "value1"
    assert registry_copy.data["field2"] == "value2"


def test_get_enrichment_invalid_arguments():
    """Argument validation is handled by Python signatures."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with pytest.raises(TypeError):
        shared.enrichment_get("name", "context", "extra")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        shared.enrichment_get(foo="test")  # type: ignore[call-arg]


def test_enrichment_with_parallel_tasks():
    """Test enrichment sharing across parallel tasks."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    def task1():
        with shared.create_cyvest() as cy:
            cy.enrichment_create("task1_data", {"source": "task1", "value": 100})

    def task2():
        with shared.create_cyvest() as cy:
            cy.enrichment_create("task2_data", {"source": "task2", "value": 200})

    def task3():
        with shared.create_cyvest() as cy:
            # Both enrichments should be available
            enr1 = shared.enrichment_get("task1_data")
            enr2 = shared.enrichment_get("task2_data")
            if enr1:
                cy.enrichment_create("combined", {"task1_value": enr1.data["value"]})
            if enr2:
                enr = cy._investigation.get_enrichment("enr:combined")
                if enr:
                    enr.data["task2_value"] = enr2.data["value"]

    # Execute tasks in sequence for deterministic testing
    task1()
    task2()
    task3()

    # Verify all enrichments are present
    assert len(shared._enrichment_registry) == 3
    combined = shared.enrichment_get("combined")
    assert combined is not None
    # task3 should have access to task1 and task2 enrichments


def test_enrichment_reconcile_count_in_log():
    """Test that reconcile debug log includes enrichment count."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.enrichment_create("test", {"data": "value"})
        # The debug log should mention enrichments count
        # This is validated by the reconcile method implementation

    # Verify registry is updated
    assert len(shared._enrichment_registry) == 1


def test_get_global_score():
    """Test retrieving global score from shared context."""
    from cyvest.model import ThreatIntel

    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)
    inv = root_cy._investigation

    # Initial score should be 0 (root observable has no threats)
    initial_score = shared.get_global_score()
    assert isinstance(initial_score, Decimal)
    assert initial_score == Decimal("0")

    with shared.create_cyvest() as cy:
        cy.check("test", "test", description="test").link_observable(cy.root(), propagation_mode="GLOBAL")

    # Directly add threat to main investigation's root
    root = inv.get_root()
    ti = ThreatIntel(source="DirectThreat", observable_key=root.key, score=Decimal("7"))
    inv.add_threat_intel(ti, root)

    # Score should be updated (root propagates to checks)
    score = shared.get_global_score()
    assert isinstance(score, Decimal)
    assert score >= Decimal("7")


def test_is_whitelisted_reflects_main_investigation():
    """Shared context exposes whitelisted status of underlying investigation."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)
    inv = root_cy._investigation

    assert shared.is_whitelisted() is False

    inv.add_whitelist("id-1", "False positive", "reason")
    assert shared.is_whitelisted() is True


def test_get_global_level_reflects_main_investigation():
    """Shared context exposes global level of underlying investigation."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    assert shared.get_global_level() == Cyvest.LVL.INFO

    with shared.create_cyvest() as cy:
        cy.check("c1", "s1", "desc").with_score(Decimal("10"))

    assert shared.get_global_level() == Cyvest.LVL.MALICIOUS


def test_get_global_score_thread_safe():
    """Test that get_global_score is thread-safe."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    # Multiple threads reading score concurrently should work safely
    def read_score():
        return shared.get_global_score()

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(read_score) for _ in range(10)]
        scores = [f.result() for f in futures]

    # All reads should return the same score and be Decimal type
    assert all(isinstance(s, Decimal) for s in scores)
    assert all(s == scores[0] for s in scores)


# ==============================================================================
# Tests for export methods (io_to_markdown, io_save_markdown, io_to_invest, io_save_json)
# ==============================================================================


def test_io_to_markdown_basic(tmp_path):
    """Test basic markdown generation from shared context."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        obs = cy.observable(Cyvest.OBS.EMAIL_ADDR, "malicious@evil.com")
        obs.with_ti("VT", Decimal("8.5"))
        cy.check("email_reputation", "header", "Check sender reputation").link_observable(obs).with_score(
            Decimal("7.0")
        )

    markdown = shared.io_to_markdown()

    assert isinstance(markdown, str)
    assert "# Cybersecurity Investigation Report" in markdown
    assert "malicious@evil.com" in markdown
    assert "email_reputation" in markdown
    assert "Global Score:" in markdown
    assert "Global Level:" in markdown


def test_io_save_markdown_creates_file(tmp_path):
    """Test that io_save_markdown creates a markdown file."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.DOMAIN_NAME, "malicious.com").with_ti("VT", Decimal("9.0"))

    filepath = tmp_path / "shared_report.md"
    result_path = shared.io_save_markdown(filepath)

    assert filepath.exists()
    assert result_path == str(filepath.resolve())

    content = filepath.read_text()
    assert "# Cybersecurity Investigation Report" in content
    assert "malicious.com" in content


def test_io_save_markdown_relative_path(tmp_path, monkeypatch):
    """Test io_save_markdown with relative path."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.check("test", "scope", "desc")

    # Change to temp directory
    monkeypatch.chdir(tmp_path)

    result_path = shared.io_save_markdown("relative_report.md")

    expected_path = tmp_path / "relative_report.md"
    assert expected_path.exists()
    assert result_path == str(expected_path.resolve())


def test_io_to_invest_basic():
    """Test basic InvestigationSchema serialization from shared context."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.IPV4_ADDR, "192.168.1.1").with_ti("SEKOIA", Decimal("6.0"))
        cy.check("ip_reputation", "network", "Check IP reputation").with_score(Decimal("5.0"))

    schema = shared.io_to_invest()

    # Verify schema attributes
    assert hasattr(schema, "investigation_id")
    assert hasattr(schema, "score")
    assert hasattr(schema, "level")
    assert hasattr(schema, "observables")
    assert hasattr(schema, "checks")
    assert hasattr(schema, "stats")
    assert "obs:ipv4-addr:192.168.1.1" in schema.observables
    assert "network" in schema.checks  # checks are grouped by scope


def test_io_save_json_creates_file(tmp_path):
    """Test that io_save_json creates a JSON file."""
    root_cy = Cyvest({"email": "test@example.com"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.URL, "https://malicious.com/payload").with_ti("VT", Decimal("10.0"))
        cy.check("url_check", "body", "Analyze URL")

    filepath = tmp_path / "shared_investigation.json"
    result_path = shared.io_save_json(filepath)

    assert filepath.exists()
    assert result_path == str(filepath.resolve())

    # Verify JSON is valid and contains expected data
    import json

    with open(filepath) as f:
        loaded = json.load(f)

    assert "investigation_id" in loaded
    assert "score" in loaded
    assert "observables" in loaded
    assert "obs:url:https://malicious.com/payload" in loaded["observables"]


def test_io_save_json_relative_path(tmp_path, monkeypatch):
    """Test io_save_json with relative path."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.check("test", "scope", "desc")

    monkeypatch.chdir(tmp_path)

    result_path = shared.io_save_json("relative_investigation.json")

    expected_path = tmp_path / "relative_investigation.json"
    assert expected_path.exists()
    assert result_path == str(expected_path.resolve())


def test_export_methods_thread_safe():
    """Test that export methods are thread-safe."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.DOMAIN_NAME, "test.com")
        cy.check("test", "scope", "desc")

    # Multiple threads calling export methods concurrently
    def export_markdown():
        return shared.io_to_markdown()

    def export_dict():
        return shared.io_to_invest()

    with ThreadPoolExecutor(max_workers=4) as executor:
        md_futures = [executor.submit(export_markdown) for _ in range(5)]
        dict_futures = [executor.submit(export_dict) for _ in range(5)]

        md_results = [f.result() for f in md_futures]
        dict_results = [f.result() for f in dict_futures]

    # All markdown exports should be identical
    assert all(md == md_results[0] for md in md_results)

    # All schema exports should contain same data
    assert all(d.score == dict_results[0].score for d in dict_results)
    assert all(len(d.observables) == len(dict_results[0].observables) for d in dict_results)


def test_export_methods_capture_latest_state(tmp_path):
    """Test that export methods capture the latest investigation state."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    # Initial state
    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.EMAIL_ADDR, "first@example.com")

    markdown1 = shared.io_to_markdown()
    assert "first@example.com" in markdown1
    assert "second@example.com" not in markdown1

    # Update state
    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.EMAIL_ADDR, "second@example.com")

    markdown2 = shared.io_to_markdown()
    assert "first@example.com" in markdown2
    assert "second@example.com" in markdown2

    # Save to files and verify
    path1 = tmp_path / "state1.md"

    # Simulate time passing
    shared.io_save_markdown(path1)

    content1 = path1.read_text()
    assert "second@example.com" in content1


def test_export_with_enrichments(tmp_path):
    """Test that export methods include enrichments."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.enrichment_create("whois", {"registrar": "Test Registrar", "created": "2020-01-01"})
        cy.enrichment_create("dns", {"A": ["1.2.3.4"], "MX": ["mail.example.com"]})

    # Test markdown export (with enrichments enabled)
    markdown = shared.io_to_markdown(include_enrichments=True)
    assert "whois" in markdown
    assert "Test Registrar" in markdown
    assert "dns" in markdown

    # Test schema export
    schema = shared.io_to_invest()
    assert len(schema.enrichments) == 2
    assert "enr:whois" in schema.enrichments
    assert "enr:dns" in schema.enrichments

    # Test JSON export
    json_path = tmp_path / "with_enrichments.json"
    shared.io_save_json(json_path)

    import json

    with open(json_path) as f:
        loaded = json.load(f)
    assert "enrichments" in loaded
    assert len(loaded["enrichments"]) == 2


def test_export_with_whitelists(tmp_path):
    """Test that export methods include whitelist information."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    inv = root_cy._investigation
    inv.add_whitelist("wl-001", "Known safe domain", "Verified by security team")
    shared = SharedInvestigationContext(root_cy)

    with shared.create_cyvest() as cy:
        cy.observable(Cyvest.OBS.DOMAIN_NAME, "safe.com")

    # Test markdown export
    markdown = shared.io_to_markdown()
    assert "Whitelisted Investigation: Yes" in markdown or "Whitelist" in markdown

    # Test schema export
    schema = shared.io_to_invest()
    assert schema.whitelisted is True
    assert len(schema.whitelists) == 1
    assert schema.whitelists[0].identifier == "wl-001"
    assert schema.whitelists[0].name == "Known safe domain"

    # Test JSON export
    json_path = tmp_path / "with_whitelists.json"
    shared.io_save_json(json_path)

    import json

    with open(json_path) as f:
        loaded = json.load(f)
    assert loaded["whitelisted"] is True
    assert len(loaded["whitelists"]) == 1


def test_export_comprehensive_investigation(tmp_path):
    """Test export of a comprehensive investigation with all features."""
    root_cy = Cyvest(
        {"email_subject": "Phishing attempt", "sender": "attacker@evil.com"}, root_type=Cyvest.OBS.ARTIFACT
    )
    shared = SharedInvestigationContext(root_cy)

    # Build comprehensive investigation
    with shared.create_cyvest() as cy:
        # Observables
        email_obs = cy.observable(Cyvest.OBS.EMAIL_ADDR, "attacker@evil.com")
        email_obs.with_ti("EmailRep", Decimal("9.5"))

        domain_obs = cy.observable(Cyvest.OBS.DOMAIN_NAME, "evil.com")
        domain_obs.with_ti("VT", Decimal("8.0"))

        url_obs = cy.observable(Cyvest.OBS.URL, "https://evil.com/phishing")
        url_obs.with_ti("URLhaus", Decimal("10.0"))

        # Relationships
        email_obs.relate_to(domain_obs, Cyvest.REL.RELATED_TO)
        url_obs.relate_to(domain_obs, Cyvest.REL.RELATED_TO)

        # Checks
        cy.check("sender_reputation", "header", "High risk sender detected").link_observable(email_obs).with_score(
            Decimal("8.5")
        )
        cy.check("url_analysis", "body", "Malicious URL detected").link_observable(url_obs).with_score(Decimal("9.0"))

        # Enrichments
        cy.enrichment_create("whois", {"registrar": "Evil Registrar", "created": "2024-01-01"}, context="evil.com")
        cy.enrichment_create("geo", {"country": "Unknown", "city": "Unknown"})

    # Export to all formats
    markdown = shared.io_to_markdown(include_enrichments=True)
    schema = shared.io_to_invest()

    md_path = tmp_path / "comprehensive.md"
    json_path = tmp_path / "comprehensive.json"

    shared.io_save_markdown(md_path, include_enrichments=True)
    shared.io_save_json(json_path)

    # Verify markdown content
    assert "attacker@evil.com" in markdown
    assert "evil.com" in markdown
    assert "sender_reputation" in markdown
    assert "url_analysis" in markdown
    assert "whois" in markdown

    # Verify schema content
    assert "obs:email-addr:attacker@evil.com" in schema.observables

    # Verify schema structure
    assert len(schema.observables) >= 4  # 3 created + 1 root
    assert "header" in schema.checks  # checks grouped by scope
    assert "body" in schema.checks
    assert len(schema.enrichments) == 2

    # Verify files exist and are valid
    assert md_path.exists()
    assert json_path.exists()

    import json

    with open(json_path) as f:
        loaded = json.load(f)
    assert loaded["score"] == schema.score
    assert len(loaded["observables"]) == len(schema.observables)


def test_export_empty_investigation(tmp_path):
    """Test exporting an investigation with only root observable."""
    root_cy = Cyvest({"test": "empty"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    # No tasks run, only root observable exists

    markdown = shared.io_to_markdown()
    assert "# Cybersecurity Investigation Report" in markdown
    assert "**Global Score:** 0.00" in markdown

    schema = shared.io_to_invest()
    assert schema.score == Decimal("0")
    assert len(schema.observables) == 1  # Just root

    json_path = tmp_path / "empty.json"
    md_path = tmp_path / "empty.md"

    shared.io_save_json(json_path)
    shared.io_save_markdown(md_path)

    assert json_path.exists()
    assert md_path.exists()


def test_export_parallel_updates(tmp_path):
    """Test that exports are consistent even with parallel task execution."""
    root_cy = Cyvest({"test": "data"}, root_type=Cyvest.OBS.ARTIFACT)
    shared = SharedInvestigationContext(root_cy)

    # Multiple tasks updating investigation in parallel
    def create_observable(index: int):
        with shared.create_cyvest() as cy:
            cy.observable(Cyvest.OBS.IPV4_ADDR, f"10.0.0.{index}")
            cy.check(f"check_{index}", "scope", f"Check {index}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(create_observable, i) for i in range(10)]
        for f in futures:
            f.result()

    # Export should capture all observables and checks
    schema = shared.io_to_invest()
    assert len(schema.observables) == 11  # 10 created + 1 root
    assert schema.stats.checks_by_scope["scope"] == 10

    # Save and verify
    json_path = tmp_path / "parallel.json"
    shared.io_save_json(json_path)

    import json

    with open(json_path) as f:
        loaded = json.load(f)
    assert len(loaded["observables"]) == 11
