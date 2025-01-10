```markdown
# Suite au hack de Cryptobottle, voici ce que j'ai mis au point

# Smart Contract Analyzer

Ce projet est un outil d’analyse de transactions et de contrats intelligents sur la blockchain Polygon.  
Il permet :  
- D’analyser des transactions suspectes,  
- De détecter des changements d’implémentation dans des contrats proxy,  
- De tracer les interactions entre contrats,  
- De générer des rapports détaillés sur l’historique des événements.

---

## Table des matières

1. [Prérequis](#prérequis)  
2. [Installation](#installation)  
3. [Configuration](#configuration)  
4. [Utilisation](#utilisation)  
5. [Structure du projet](#structure-du-projet)  
6. [Fonctionnalités](#fonctionnalités)  
7. [Exemple de sortie](#exemple-de-sortie)  
8. [Dépannage](#dépannage)  
9. [Contributions](#contributions)  
10. [Licence](#licence)

---

## Prérequis

Assurez-vous d’avoir les éléments suivants :  
- Node.js (version 16 ou supérieure)  
- NPM ou Yarn  
- Une clé API PolygonScan  
- Un RPC valide pour la blockchain Polygon  

---

## Installation

```bash
npm install
```

---

## Configuration

1. Créer un fichier `.env` à la racine du projet :

```bash
touch .env
```

2. Ajoutez vos configurations dans `.env` :

```bash
POLYGON_RPC=https://polygon-rpc.com
POLYGONSCAN_API_KEY=<votre-api-key-polygonscan>
```

---

## Utilisation

Pour lancer l’analyse d’un hack :

```bash
node analyze_hack.js
```

Vous pouvez personnaliser les variables suivantes dans `analyze_hack.js` :

```js
const HACK_TX = '<hash_de_la_transaction_suspecte>';
const VICTIM_CONTRACT = '<adresse_du_contrat_victime>';
const HACKER_ADDRESS = '<adresse_du_hacker>';
const KNOWN_IMPLEMENTATION = '<adresse_de_l_implémentation_attendue>';
```

---

## Structure du projet

```
smart-contract-analyzer/
│
├── analyze_hack.js           # Script principal d'analyse
├── smart-contract-analyzer.js # Classe principale de l'analyse des contrats
├── .env                      # Configuration des clés et RPC
├── package.json              # Fichier de gestion des dépendances
└── README.md                 # Documentation du projet
```

---

## Fonctionnalités

### 🔍 Analyse de la transaction suspecte
- Décodage des logs et des traces internes  
- Récupération des changements d’implémentation  

### 📄 Analyse du contrat victime
- Détection des contrats proxy et récupération des transactions associées  
- Identification des fonctions critiques (`UPGRADE_TO`, `CHANGE_ADMIN`, `UPGRADE_TO_AND_CALL`)  

### 🕸️ Traçage des interactions entre contrats
- Parcours des appels contractuels pour détecter les interactions entre contrats  

### 🚨 Détection des actions suspectes
- Vérification des signatures de fonctions  
- Marquage des appels contract-to-contract suspects  

### 📚 Historique des changements d’implémentation
- Analyse de l’évolution des implémentations sur plusieurs blocs  

### 📁 Génération de rapports
- Export en JSON et en fichier texte  

---

## Exemple de sortie

### Console :

```
🔍 Démarrage de l'analyse du hack...
📄 Analyse du contrat victime 0x8B5Ea07B...
🚨 Actions suspectes détectées :
- Transaction 0xe97e...53ca
  De: 0x6d24389...
  À: 0x4660083D...
  Raison: suspicious_signature
📚 Historique des implémentations :
- Block 2000000: 0x4660083D...
```

### Rapport JSON généré :

```json
{
  "metadata": {
    "analyzedAt": "2025-01-10T14:00:00Z",
    "hackTransaction": "0xe97e555d9423cf40a...",
    "victimContract": "0x8B5Ea07B...",
    "hackerAddress": "0x6d24389C...",
    "knownImplementation": "0x4660083D..."
  },
  "analysis": {
    "hackDetails": {
      "transaction": { "...": "..." },
      "stateChanges": {
        "before": {
          "implementation": "0x...",
          "admin": "0x..."
        },
        "after": {
          "implementation": "0x...",
          "admin": "0x..."
        }
      }
    },
    "suspiciousActions": [
      {
        "hash": "0xe97e555d9423...",
        "from": "0x6d24389C...",
        "to": "0x4660083D...",
        "reason": ["suspicious_signature"],
        "timestamp": "2025-01-10T12:45:00Z"
      }
    ],
    "implementationHistory": [
      {
        "blockNumber": 2000000,
        "implementation": "0x4660083D..."
      }
    ]
  }
}
```

---

## Dépannage

1. **Web3ValidatorError: value "" must pass "address" validation**  
   - Vérifiez que les adresses passées aux appels Web3 sont correctes.  
   - Ajoutez une vérification des adresses dans les fonctions (`traceContractCalls`, `isContract`).  

2. **AbiError: Parameter decoding error**  
   - Assurez-vous que l’ABI des fonctions (`UPGRADE_TO_AND_CALL`, etc.) est correctement définie.  
   - Ajoutez une vérification avec un log pour afficher l’ABI utilisée.  

---

## Contributions

Les contributions sont les bienvenues !  
N’hésitez pas à ouvrir une issue ou une pull request si vous souhaitez améliorer le projet.

---

## Licence

Ce projet est distribué sous la licence **MIT**.  
Vous êtes libre de l’utiliser, de le modifier et de le redistribuer tant que les termes de la licence sont respectés.
```
