from pathlib import Path

from . import RULES, RULESET_VERSION


def main() -> None:
    lines = [
        "# Catalogue des règles",
        "",
        f"Version du jeu de règles : {RULESET_VERSION}",
        "",
        "Une détection est un indicateur à examiner, pas une preuve de compromission.",
        "",
    ]
    for r in RULES:
        lines += [
            f"## {r.id} : {r.title}",
            f"- **Catégorie** : {r.category}",
            f"- **Gravité** : {r.severity}",
            f"- **Version de la règle** : {r.version}",
            f"- **Explication** : {r.explanation}",
            f"- **Recommandation** : {r.recommendation}",
            f"- **Limites** : {r.limits}",
            "",
        ]
    out = Path(__file__).resolve().parents[3] / "docs" / "rules.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Écrit : {out}")


if __name__ == "__main__":
    main()
