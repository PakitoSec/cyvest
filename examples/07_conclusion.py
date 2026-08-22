"""
Example 7: An AI analysis that concludes

An LLM asked to review a case does not bring new evidence — it renders a verdict on what is
already there. Recorded as an ordinary finding it would double-count what it just read; recorded
as a conclusion it only supplies what the case is missing.
"""

from logurich import get_logger, init_logger

from cyvest import Cyvest

logger = get_logger(__name__)


def build_case() -> Cyvest:
    cv = Cyvest(root_data={"type": "email", "subject": "Facture impayée"})

    url = (
        cv.observable(cv.OBS.URL, "https://invoice-portal.example/pay", internal=False)
        .with_ti("virustotal", verdict=cv.VERDICT.NOTABLE, weight=1.2, comment="2/94 moteurs")
        .relate_to(cv.root(), cv.REL.RELATED_TO)
    )
    cv.finding("spf_fail", "SPF invalide", verdict=cv.VERDICT.SUSPICIOUS, weight=2.0)
    cv.finding("url_reputation", "URL faiblement signalée", subject=url).link_observable(url, cv.SCOPE.ALL)
    return cv


def main() -> None:
    cv = build_case()
    logger.info("Avant l'analyse IA : %.2f (%s)", cv.get_global_score(), cv.get_global_verdict())

    # The analysis read the findings above and concludes; it states a verdict, never a weight.
    conclusion = cv.conclusion(
        "ai_review",
        "Analyse IA",
        comment="Chaîne d'usurpation cohérente avec une campagne de facturation frauduleuse.",
        verdict=cv.VERDICT.MALICIOUS,
        confidence=0.8,
    )
    logger.info(
        "Après : %.2f (%s) — la conclusion n'a apporté que %.2f",
        cv.get_global_score(),
        cv.get_global_verdict(),
        conclusion.applied_floor,
    )

    # A second analyser agreeing changes nothing: conclusions do not compound.
    second = cv.conclusion("ai_second_opinion", "Second avis IA", verdict=cv.VERDICT.MALICIOUS)
    logger.info(
        "Second avis : total toujours %.2f — les deux conclusions se partagent %.2f, pas 2 × 5.00",
        cv.get_global_score(),
        conclusion.applied_floor + second.applied_floor,
    )

    cv.finalize_relationships()
    cv.display_summary()


if __name__ == "__main__":
    init_logger("INFO")
    main()
