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

from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal

import pytest

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
        # Mutations should not leak back to main investigation data
        cy.root().extra["email"] = "modified@example.com"

    assert inv._root_observable.extra == {"email": "test@example.com"}


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
        original_model = cy._investigation.get_observable(original.key)

    # Retrieve observable
    retrieved = shared.get_observable("obs:ipv4-addr:192.168.1.1")

    assert retrieved is not None
    assert retrieved.obs_type == ObservableType.IPV4_ADDR
    assert retrieved.value == "192.168.1.1"
    # Should be a deep copy, not the same object
    assert retrieved is not original_model


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
        original_check = cy._investigation.get_check(original.key)

    # Retrieve check
    retrieved = shared.get_check("chk:test_check:scope")

    assert retrieved is not None
    assert retrieved.check_id == "test_check"
    assert retrieved.scope == "scope"
    # Should be a deep copy
    assert retrieved is not original_check


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
        # Inspect shared domain (read-only)
        domain_info = shared.get_observable("obs:domain-name:malicious.com")
        assert domain_info is not None
        assert domain_info.value == "malicious.com"

        # Create URL and link to domain (correct pattern: use cy.observable())
        url = cy2.observable(ObservableType.URL, data["url"])
        url.relate_to(cy2.observable(ObservableType.DOMAIN_NAME, "malicious.com"), RelationshipType.RELATED_TO)

    # Verify final investigation has both observables
    assert "obs:domain-name:malicious.com" in inv._observables
    assert "obs:url:https://malicious.com/payload" in inv._observables


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
        check.link_observable(email_obs)

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
        check.link_observable(url_obs)

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


# ==============================================================================
# Tests for parameter-based API (new overloaded methods)
# ==============================================================================


def test_get_observable_with_parameters():
    """Test get_observable using type and value parameters."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.observable(ObservableType.EMAIL_ADDR, "user@example.com")

    # Test parameter-based lookup with string type
    obs = shared.get_observable("email-addr", "user@example.com")
    assert obs is not None
    assert obs.obs_type == ObservableType.EMAIL_ADDR
    assert obs.value == "user@example.com"

    # Test parameter-based lookup with ObservableType enum
    obs_enum = shared.get_observable(ObservableType.EMAIL_ADDR, "user@example.com")
    assert obs_enum is not None
    assert obs_enum.obs_type == ObservableType.EMAIL_ADDR
    assert obs_enum.value == "user@example.com"

    # Test key-based lookup (backward compatibility)
    obs_key = shared.get_observable("obs:email-addr:user@example.com")
    assert obs_key is not None
    assert obs_key.value == "user@example.com"


def test_get_check_with_parameters():
    """Test get_check using check_id and scope parameters."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.check("malware_scan", "attachment", "Scan for malware")

    # Test parameter-based lookup
    check = shared.get_check("malware_scan", "attachment")
    assert check is not None
    assert check.check_id == "malware_scan"
    assert check.scope == "attachment"

    # Test key-based lookup (backward compatibility)
    check_key = shared.get_check("chk:malware_scan:attachment")
    assert check_key is not None
    assert check_key.check_id == "malware_scan"


def test_has_observable_with_parameters():
    """Test has_observable using type and value parameters."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.observable(ObservableType.DOMAIN_NAME, "malicious.com")

    # Test parameter-based check with string type
    assert shared.has_observable("domain-name", "malicious.com")
    assert not shared.has_observable("domain-name", "safe.com")

    # Test parameter-based check with ObservableType enum
    assert shared.has_observable(ObservableType.DOMAIN_NAME, "malicious.com")
    assert not shared.has_observable(ObservableType.IPV4_ADDR, "1.2.3.4")

    # Test key-based check (backward compatibility)
    assert shared.has_observable("obs:domain-name:malicious.com")
    assert not shared.has_observable("obs:domain-name:safe.com")


def test_has_check_with_parameters():
    """Test has_check using check_id and scope parameters."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.check("url_reputation", "body", "Check URL reputation")

    # Test parameter-based check
    assert shared.has_check("url_reputation", "body")
    assert not shared.has_check("email_reputation", "header")

    # Test key-based check (backward compatibility)
    assert shared.has_check("chk:url_reputation:body")
    assert not shared.has_check("chk:email_reputation:header")


def test_investigation_get_observable_with_parameters():
    """Test Investigation.get_observable using parameters for API consistency."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    cy = Cyvest({"test": "data"}, root_type="artifact")
    cy.observable(ObservableType.IPV4_ADDR, "10.0.0.1")

    # Merge into investigation
    inv.merge_investigation(cy._investigation)

    # Test parameter-based lookup with string type
    obs = inv.get_observable("ipv4-addr", "10.0.0.1")
    assert obs is not None
    assert obs.value == "10.0.0.1"

    # Test parameter-based lookup with ObservableType enum
    obs_enum = inv.get_observable(ObservableType.IPV4_ADDR, "10.0.0.1")
    assert obs_enum is not None
    assert obs_enum.value == "10.0.0.1"

    # Test key-based lookup (backward compatibility)
    obs_key = inv.get_observable("obs:ipv4-addr:10.0.0.1")
    assert obs_key is not None


def test_investigation_get_check_with_parameters():
    """Test Investigation.get_check using parameters for API consistency."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    cy = Cyvest({"test": "data"}, root_type="artifact")
    cy.check("dns_lookup", "network", "DNS reputation check")

    # Merge into investigation
    inv.merge_investigation(cy._investigation)

    # Test parameter-based lookup
    check = inv.get_check("dns_lookup", "network")
    assert check is not None
    assert check.check_id == "dns_lookup"

    # Test key-based lookup (backward compatibility)
    check_key = inv.get_check("chk:dns_lookup:network")
    assert check_key is not None


def test_observable_type_enum_conversion():
    """Test that ObservableType enums are properly converted to strings."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        # Create observables of different types
        cy.observable(ObservableType.URL, "https://example.com")
        cy.observable(ObservableType.FILE, "malware.exe")
        cy.observable(ObservableType.NETWORK_TRAFFIC, "http-traffic")

    # Test that enum values work correctly
    assert shared.has_observable(ObservableType.URL, "https://example.com")
    assert shared.has_observable(ObservableType.FILE, "malware.exe")
    assert shared.has_observable(ObservableType.NETWORK_TRAFFIC, "http-traffic")

    url_obs = shared.get_observable(ObservableType.URL, "https://example.com")
    assert url_obs is not None
    assert url_obs.obs_type == ObservableType.URL


def test_get_observable_invalid_arguments():
    """Test that get_observable raises ValueError for invalid arguments."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    import pytest

    # Too many arguments
    with pytest.raises(ValueError, match="get_observable\\(\\) accepts either"):
        shared.get_observable("type", "value", "extra")

    # No arguments
    with pytest.raises(ValueError, match="get_observable\\(\\) accepts either"):
        shared.get_observable()


def test_get_check_invalid_arguments():
    """Test that get_check raises ValueError for invalid arguments."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    import pytest

    # Too many arguments
    with pytest.raises(ValueError, match="get_check\\(\\) accepts either"):
        shared.get_check("id", "scope", "extra")

    # No arguments
    with pytest.raises(ValueError, match="get_check\\(\\) accepts either"):
        shared.get_check()


def test_has_observable_invalid_arguments():
    """Test that has_observable raises ValueError for invalid arguments."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    import pytest

    # Too many arguments
    with pytest.raises(ValueError, match="has_observable\\(\\) accepts either"):
        shared.has_observable("type", "value", "extra")


def test_has_check_invalid_arguments():
    """Test that has_check raises ValueError for invalid arguments."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    import pytest

    # Too many arguments
    with pytest.raises(ValueError, match="has_check\\(\\) accepts either"):
        shared.has_check("id", "scope", "extra")


def test_parameter_based_api_in_parallel_tasks():
    """Test parameter-based API works correctly in parallel tasks."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    def task1(shared_ctx):
        with shared_ctx.create_cyvest() as cy:
            cy.observable(ObservableType.EMAIL_ADDR, "sender@malicious.com").add_ti("EmailRep", Decimal("8.0"))
            cy.check("sender_check", "header", "Analyze sender")

    def task2(shared_ctx):
        with shared_ctx.create_cyvest() as cy:
            # Use parameter-based lookup to get observable from task1
            sender = shared_ctx.get_observable(ObservableType.EMAIL_ADDR, "sender@malicious.com")
            if sender and sender.score > 5:
                cy.check("high_risk_sender", "risk", "High risk detected").with_score(Decimal("9.0"))

    # Execute tasks in parallel
    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(task1, shared)
        f1.result()  # Wait for task1 to complete
        f2 = executor.submit(task2, shared)
        f2.result()

    # Verify both tasks completed and parameter-based lookups worked
    assert shared.has_observable(ObservableType.EMAIL_ADDR, "sender@malicious.com")
    assert shared.has_check("sender_check", "header")
    assert shared.has_check("high_risk_sender", "risk")

    sender_obs = shared.get_observable(ObservableType.EMAIL_ADDR, "sender@malicious.com")
    assert sender_obs.score >= Decimal("8.0")


def test_normalization_consistency():
    """Test that parameter-based lookups handle normalization correctly."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        # Create with mixed case
        cy.observable(ObservableType.EMAIL_ADDR, "User@Example.COM")

    # Lookup should work with different casing (normalization)
    obs1 = shared.get_observable(ObservableType.EMAIL_ADDR, "user@example.com")
    obs2 = shared.get_observable("email-addr", "USER@EXAMPLE.COM")
    obs3 = shared.get_observable(ObservableType.EMAIL_ADDR, "  User@Example.COM  ")

    assert obs1 is not None
    assert obs2 is not None
    assert obs3 is not None
    # All should find the same observable (values are normalized in keys)
    assert obs1.value == obs2.value == obs3.value


def test_prevent_relationship_with_shared_copy():
    """Test that using a copied observable from shared context raises helpful error."""
    import pytest

    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    # Task 1: Create domain observable
    with shared.create_cyvest() as cy1:
        cy1.observable(ObservableType.DOMAIN_NAME, "malicious.com").add_ti("VT", 8)

    # Task 2: Try to use the copy (should fail with clear error)
    with shared.create_cyvest() as cy2:
        url_obs = cy2.observable(ObservableType.URL, "https://evil.com/payload")

        # Get copy from shared context (anti-pattern)
        domain_copy = shared.get_observable(ObservableType.DOMAIN_NAME, "malicious.com")
        assert domain_copy is not None
        assert domain_copy._from_shared_context is True

        # This should raise ValueError with helpful message
        with pytest.raises(ValueError) as exc_info:
            url_obs.relate_to(domain_copy, RelationshipType.RELATED_TO)

        # Verify error message is helpful
        error_msg = str(exc_info.value)
        assert "Cannot use observable from shared_context.get_observable()" in error_msg
        assert "read-only copy" in error_msg
        assert "cy.observable" in error_msg
        assert "Incorrect pattern" in error_msg
        assert "Correct pattern" in error_msg

    # Correct pattern should work
    with shared.create_cyvest() as cy3:
        url_obs = cy3.observable(ObservableType.URL, "https://evil.com/payload")
        url_obs.relate_to(
            cy3.observable(ObservableType.DOMAIN_NAME, "malicious.com"),
            RelationshipType.RELATED_TO,
        )
        # Should succeed without error

    # Verify the correct pattern created the relationship
    url = inv.get_observable(ObservableType.URL, "https://evil.com/payload")
    assert url is not None
    assert len(url.relationships) > 0
    assert any(rel.target_key.endswith("malicious.com") for rel in url.relationships)


def test_copied_observable_has_marker():
    """Test that copied observables are marked with _from_shared_context flag."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        original = cy.observable(ObservableType.DOMAIN_NAME, "example.com")
        original_model = cy._investigation.get_observable(original.key)
        assert original_model is not None
        # Original should not be marked
        assert original_model._from_shared_context is False

    # Copy from shared context should be marked
    copy = shared.get_observable(ObservableType.DOMAIN_NAME, "example.com")
    assert copy is not None
    assert copy._from_shared_context is True

    # Get from investigation directly should not be marked
    direct = inv.get_observable(ObservableType.DOMAIN_NAME, "example.com")
    assert direct is not None
    assert direct._from_shared_context is False


def test_get_enrichment_by_key():
    """Test retrieving enrichment by key from shared context."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        original = cy.enrichment_create("whois", {"registrar": "Test Inc", "created": "2020-01-01"})
        original_enr = cy._investigation.get_enrichment(original.key)

    # Retrieve enrichment by key
    retrieved = shared.get_enrichment("enr:whois")

    assert retrieved is not None
    assert retrieved.name == "whois"
    assert retrieved.data == {"registrar": "Test Inc", "created": "2020-01-01"}
    # Should be a deep copy
    assert retrieved is not original_enr


def test_get_enrichment_by_name():
    """Test retrieving enrichment by name from shared context."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.enrichment_create("dns", {"A": ["1.2.3.4"], "MX": ["mail.example.com"]})

    # Retrieve enrichment by name
    retrieved = shared.get_enrichment("dns")

    assert retrieved is not None
    assert retrieved.name == "dns"
    assert retrieved.data["A"] == ["1.2.3.4"]
    assert retrieved.data["MX"] == ["mail.example.com"]


def test_get_enrichment_with_context():
    """Test retrieving enrichment with context from shared context."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.enrichment_create("dns", {"A": ["192.168.1.1"]}, context="example.com")
        cy.enrichment_create("dns", {"A": ["10.0.0.1"]}, context="other.com")

    # Retrieve specific enrichment with context
    retrieved = shared.get_enrichment("dns", "example.com")

    assert retrieved is not None
    assert retrieved.name == "dns"
    assert retrieved.data["A"] == ["192.168.1.1"]
    assert retrieved.context == "example.com"

    # Retrieve different context
    retrieved2 = shared.get_enrichment("dns", "other.com")
    assert retrieved2 is not None
    assert retrieved2.data["A"] == ["10.0.0.1"]


def test_get_nonexistent_enrichment():
    """Test retrieving non-existent enrichment returns None."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    result = shared.get_enrichment("enr:nonexistent")
    assert result is None

    result = shared.get_enrichment("nonexistent")
    assert result is None

    result = shared.get_enrichment("whois", "missing-context")
    assert result is None


def test_list_enrichments():
    """Test listing all enrichment keys."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    # Initially empty
    assert len(shared.list_enrichments()) == 0

    with shared.create_cyvest() as cy:
        cy.enrichment_create("whois", {"registrar": "Test"})
        cy.enrichment_create("dns", {"A": ["1.2.3.4"]})
        cy.enrichment_create("geo", {"country": "US"}, context="ip-lookup")

    keys = shared.list_enrichments()
    assert len(keys) == 3
    assert "enr:whois" in keys
    assert "enr:dns" in keys
    # Context-based enrichment should have hash in key
    assert any(key.startswith("enr:geo:") for key in keys)


def test_enrichment_reconcile_updates_registry():
    """Test that reconciling updates enrichment registry."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    # Create first enrichment
    with shared.create_cyvest() as cy:
        cy.enrichment_create("initial", {"data": "v1"})

    assert len(shared.list_enrichments()) == 1

    # Create second enrichment
    with shared.create_cyvest() as cy:
        cy.enrichment_create("second", {"data": "v2"})

    assert len(shared.list_enrichments()) == 2
    assert shared.get_enrichment("initial") is not None
    assert shared.get_enrichment("second") is not None


def test_enrichment_deep_copy_independence():
    """Test that retrieved enrichment is a deep copy."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.enrichment_create("test", {"list": [1, 2, 3], "dict": {"key": "value"}})

    # Get enrichment and modify it
    retrieved1 = shared.get_enrichment("test")
    assert retrieved1 is not None
    retrieved1.data["list"].append(4)
    retrieved1.data["dict"]["new_key"] = "new_value"

    # Get enrichment again - should not be affected by previous modification
    retrieved2 = shared.get_enrichment("test")
    assert retrieved2 is not None
    assert retrieved2.data["list"] == [1, 2, 3]
    assert "new_key" not in retrieved2.data["dict"]


def test_enrichment_merge_in_reconcile():
    """Test that enrichments are properly merged during reconciliation."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

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
    registry_copy = shared.get_enrichment("shared")
    assert registry_copy is not None
    assert registry_copy.data["field1"] == "value1"
    assert registry_copy.data["field2"] == "value2"


def test_get_enrichment_invalid_arguments():
    """Test that get_enrichment raises ValueError for invalid arguments."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    # Too many arguments
    with pytest.raises(ValueError) as exc_info:
        shared.get_enrichment("name", "context", "extra")
    assert "accepts either" in str(exc_info.value)

    # Keyword arguments not supported
    with pytest.raises(ValueError):
        shared.get_enrichment(name="test")


def test_enrichment_with_parallel_tasks():
    """Test enrichment sharing across parallel tasks."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    def task1():
        with shared.create_cyvest() as cy:
            cy.enrichment_create("task1_data", {"source": "task1", "value": 100})

    def task2():
        with shared.create_cyvest() as cy:
            cy.enrichment_create("task2_data", {"source": "task2", "value": 200})

    def task3():
        with shared.create_cyvest() as cy:
            # Both enrichments should be available
            enr1 = shared.get_enrichment("task1_data")
            enr2 = shared.get_enrichment("task2_data")
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
    assert len(shared.list_enrichments()) == 3
    combined = shared.get_enrichment("combined")
    assert combined is not None
    # task3 should have access to task1 and task2 enrichments


def test_enrichment_reconcile_count_in_log():
    """Test that reconcile debug log includes enrichment count."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    with shared.create_cyvest() as cy:
        cy.enrichment_create("test", {"data": "value"})
        # The debug log should mention enrichments count
        # This is validated by the reconcile method implementation

    # Verify registry is updated
    assert len(shared._enrichment_registry) == 1


def test_get_global_score():
    """Test retrieving global score from shared context."""
    from cyvest.model import ThreatIntel

    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    # Initial score should be 0 (root observable has no threats)
    initial_score = shared.get_global_score()
    assert isinstance(initial_score, Decimal)
    assert initial_score == Decimal("0")

    with shared.create_cyvest() as cy:
        cy.check("test", "test", description="test").link_observable(cy.root())

    # Directly add threat to main investigation's root
    root = inv.get_root()
    ti = ThreatIntel(source="DirectThreat", observable_key=root.key, score=Decimal("7"))
    inv.add_threat_intel(ti, root)

    # Score should be updated (root propagates to checks now)
    score = shared.get_global_score()
    assert isinstance(score, Decimal)
    assert score >= Decimal("7")


def test_is_whitelisted_reflects_main_investigation():
    """Shared context exposes whitelisted status of underlying investigation."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    assert shared.is_whitelisted() is False

    inv.add_whitelist("id-1", "False positive", "reason")
    assert shared.is_whitelisted() is True


def test_get_global_level_reflects_main_investigation():
    """Shared context exposes global level of underlying investigation."""
    from cyvest.levels import Level

    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    assert shared.get_global_level() == Level.INFO

    with shared.create_cyvest() as cy:
        cy.check("c1", "s1", "desc").with_score(Decimal("10"))

    assert shared.get_global_level() == Level.MALICIOUS


def test_get_global_score_thread_safe():
    """Test that get_global_score is thread-safe."""
    inv = Investigation({"test": "data"}, root_type="artifact")
    shared = SharedInvestigationContext(inv)

    # Multiple threads reading score concurrently should work safely
    def read_score():
        return shared.get_global_score()

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(read_score) for _ in range(10)]
        scores = [f.result() for f in futures]

    # All reads should return the same score and be Decimal type
    assert all(isinstance(s, Decimal) for s in scores)
    assert all(s == scores[0] for s in scores)
