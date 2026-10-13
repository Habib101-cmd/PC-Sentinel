# Catalogue des règles

Version du jeu de règles : 0.2.0

Une détection est un indicateur à examiner, pas une preuve de compromission.

## R002 : Protection antivirus désactivée
- **Catégorie** : Protection
- **Gravité** : Élevé
- **Version de la règle** : 1.0
- **Explication** : Un antivirus est enregistré dans Windows, mais il est signalé comme désactivé : le PC n'est plus protégé en temps réel.
- **Recommandation** : Réactivez la protection dans Sécurité Windows > Protection contre les virus.
- **Limites** : L'état est lu dans le Centre de sécurité Windows. Un produit peut le déclarer de façon inexacte.

## R003 : Aucun antivirus détecté
- **Catégorie** : Protection
- **Gravité** : Moyen
- **Version de la règle** : 1.0
- **Explication** : Aucun produit antivirus n'est enregistré dans le Centre de sécurité Windows.
- **Recommandation** : Activez Microsoft Defender ou installez une protection reconnue.
- **Limites** : Un antivirus non déclaré dans Windows ne serait pas visible par cet audit.

## R001 : Pare-feu désactivé
- **Catégorie** : Configuration
- **Gravité** : Moyen
- **Version de la règle** : 1.0
- **Explication** : Le pare-feu Windows filtre les connexions entrantes. Désactivé, le PC est plus exposé aux accès non sollicités.
- **Recommandation** : Activez le pare-feu dans Sécurité Windows > Pare-feu et protection réseau.
- **Limites** : Un pare-feu tiers peut remplir ce rôle sans que le pare-feu Windows soit actif.

## R007 : Échecs de connexion répétés
- **Catégorie** : Authentification
- **Gravité** : Moyen
- **Version de la règle** : 1.0
- **Explication** : Au moins 10 tentatives de connexion Windows ont échoué sur la période. Cela peut indiquer quelqu'un qui devine un mot de passe.
- **Recommandation** : Si ces échecs ne sont pas de votre fait, changez le mot de passe du compte et vérifiez que le bureau à distance n'est pas exposé.
- **Limites** : Le journal compte aussi des erreurs bénignes (mot de passe tapé de travers, services mal configurés). Seul le nombre est analysé, pas la source.

## R006 : Processus lancé depuis un emplacement inhabituel
- **Catégorie** : Processus
- **Gravité** : Faible
- **Version de la règle** : 1.0
- **Explication** : Ce programme s'exécute depuis un dossier temporaire, de téléchargement ou partagé, où les logiciels légitimes sont rarement installés à demeure. Certains codes malveillants utilisent ces emplacements.
- **Recommandation** : Identifiez le programme (nom du fichier, éditeur). Si vous ne l'avez pas lancé volontairement, fermez-le et faites analyser le fichier.
- **Limites** : Des installeurs et outils portables légitimes s'exécutent depuis ces dossiers. Sans droits administrateur, seuls vos propres processus sont visibles. L'agent n'envoie pas les programmes des dossiers système.

## R005 : Programme non signé au démarrage
- **Catégorie** : Démarrage
- **Gravité** : Faible
- **Version de la règle** : 1.0
- **Explication** : Ce programme se lance à chaque ouverture de session et sa signature numérique est absente ou invalide. Un éditeur identifiable est plus facile à vérifier.
- **Recommandation** : Vérifiez que vous reconnaissez ce programme (Gestionnaire des tâches > Démarrage). En cas de doute, cherchez son nom en ligne ou analysez le fichier avec un antivirus.
- **Limites** : De nombreux petits logiciels légitimes ne sont pas signés : c'est un indicateur à vérifier, pas une preuve. Seuls les programmes dont le chemin a pu être déterminé sont examinés.

## R004 : Aucun correctif Windows récent
- **Catégorie** : Mises à jour
- **Gravité** : Faible
- **Version de la règle** : 1.0
- **Explication** : Aucun correctif n'a été installé depuis plus de 60 jours. Les mises à jour corrigent des failles que des attaquants exploitent.
- **Recommandation** : Ouvrez Paramètres > Windows Update et installez les mises à jour proposées.
- **Limites** : La liste des correctifs vient de Get-HotFix, qui ne couvre pas toutes les mises à jour (pilotes, Microsoft Store, définitions antivirus).
