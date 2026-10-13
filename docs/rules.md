# Catalogue des règles

Version du jeu de règles : 0.1.0

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
