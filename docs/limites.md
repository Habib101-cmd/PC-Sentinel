# Limites connues et évolutions

## Portée de la détection

- PC Sentinel est un outil de diagnostic et de sensibilisation, pas un antivirus.
- Un audit sans alerte ne prouve pas l'absence d'attaque.
- Une alerte est un indicateur à vérifier : faux positifs possibles (logiciels non signés, installeurs lancés depuis Téléchargements).

## Limites des contrôles

- L'état de l'antivirus vient du Centre de sécurité Windows ; le décodage de `productState` (bit 0x1000) n'est pas documenté officiellement par Microsoft. Defender en mode passif est affiché « inactif » quand un autre produit est actif.
- `Get-HotFix` ne liste pas toutes les mises à jour (pilotes, Microsoft Store, définitions antivirus).
- Sans droits administrateur : échecs de connexion indisponibles, seuls les processus de l'utilisateur sont visibles.
- Une signature valide ne prouve pas qu'un programme est sûr ; « non signé » ne prouve pas qu'il est malveillant.
- La liste des processus exclut les dossiers système et est limitée à 300 chemins.

## Limites techniques

- Limiteurs de tentatives en mémoire : réinitialisés au redémarrage, non partagés entre plusieurs instances.
- Jeton JWT valable 8 h, non révocable avant expiration, conservé en `sessionStorage`.
- Certificat HTTPS local de développement ; en production, un nom de domaine et un certificat public sont nécessaires.
- Conteneurs exécutés en root ; pas de rotation des journaux.

## Non réalisé dans cette version (prévu au cahier des charges)

- Connexions réseau actives et événements réseau.
- Inventaire des logiciels installés et règle « logiciel ancien » avec source de vulnérabilités.
- Comparaison entre audits, export PDF (en attendant : imprimer le rapport en PDF depuis le navigateur), notifications, mode administrateur multi-postes, Linux et macOS.
