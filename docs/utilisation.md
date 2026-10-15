# Utilisation

1. **Créer un compte** sur l'interface (mot de passe de 12 caractères minimum).
2. **Lancer l'agent** : `python agent/audit.py`. Il affiche la liste exacte des données collectées.
3. **Confirmer** : sans réponse « o », rien n'est lu ni envoyé.
4. **Se connecter** avec les identifiants du compte. L'agent exécute les contrôles en lecture seule et affiche chacun d'eux.
5. **Consulter** le tableau de bord après « Actualiser » : état global, compteurs par gravité, recommandations principales, historique.
6. **Ouvrir le détail** d'un audit puis d'une alerte : catégorie, élément concerné, règle, explication, recommandation, limites.
7. **Exporter** : « Consulter le rapport » ou « Télécharger (HTML) ».
8. **Supprimer** un audit ou le compte entier (boutons avec confirmation).

## États d'un audit

| État                          | Signification                                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------------ |
| Aucun indicateur détecté      | Aucune règle déclenchée et tous les contrôles réalisés. Ne prouve pas l'absence d'attaque. |
| Éléments à vérifier           | Alertes de gravité faible ou moyenne, ou contrôles non réalisés.                           |
| Indicateurs à risque détectés | Au moins une alerte de gravité élevée.                                                     |

Un contrôle non réalisé (par exemple faute de droits administrateur) n'est ni bon ni mauvais : il n'a pas pu être vérifié.
