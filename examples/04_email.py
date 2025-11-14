from logurich import logger

from cyvest import Cyvest, ObservableType, RelationshipType

logger.enable("cyvest")


cy = Cyvest({"structured_email": {}}, root_type="artifact")

obs = (
    cy.observable(ObservableType.EMAIL_ADDR, "noreply@domainmalicious.com")
    .relate_to(cy.root(), relationship_type=RelationshipType.FROM)
    .relate_to(
        cy.observable(ObservableType.DOMAIN_NAME, "domainmalicious.com")
        .add_ti("VT", 2)
        .relate_to(
            cy.observable(ObservableType.IPV4_ADDR, "8.1.2.3").add_ti("SEKOIA", 1), RelationshipType.RESOLVES_TO
        ),
        RelationshipType.RELATED_TO,
    )
    .add_ti("VT", 10, "test")
    .get()
)

check_from = (
    cy.check("from-test", "header", "test email vt 10", "> ok boys")
    .link_observable(obs)
    .in_container(cy.container("test").sub_container("email"))
    .get()
)

cy.check("body-html", "body", "description", "> comment")
check_body = cy.check("body-html", "body", "description", "> commento").with_score(5)


def add_url(url, score):
    cy.check(f"body-url-{url}", "body", f"{url}", comment=f"> score: {score}").link_observable(
        cy.observable(ObservableType.URL, url)
        .add_ti("VT", score)
        .relate_to(cy.observable(ObservableType.DOMAIN_NAME, "domainmalicious.com"), RelationshipType.RESOLVES_TO)
    ).in_container(cy.container("body-urls"))


add_url("https://toto.domain.malicious.com", 1)
add_url("https://domain.com/ok/toto", 0)


cy.observable_finalize_relationships()

cy.display_summary()

cy.display_network()
