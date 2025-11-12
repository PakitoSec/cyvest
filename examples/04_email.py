from cyvest import Cyvest, ObservableType, RelationshipType

cy = Cyvest({"structured_email": {}}, root_type="artifact")

obs = (
    cy.observable(ObservableType.EMAIL_ADDR, "ok@ok.ok")
    .relate_to(cy.root(), relationship_type=RelationshipType.FROM)
    .add_ti("VT", 10, "test")
    .get()
)

cy.observable_finalize_relationships()

test = (
    cy.check("TEST", "body", "test email vt 10", "> ok boys")
    .link_observable(obs)
    .in_container(cy.container("test").sub_container("toto/ok/OK"))
    .get()
)

cy.check("azezae", "scope", "description", "> comment").in_container(cy.container("test/toto/ok/OK"))
c = cy.check("azezae", "scope", "description", "> commento").with_score(5).get()


cy.display_summary()
print(cy.check_get(c.key).comment)