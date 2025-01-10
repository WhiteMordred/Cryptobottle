// analyze_hack.js
import SmartContractAnalyzer from './smart-contract-analyzer.js';
import Web3 from 'web3';
import dotenv from 'dotenv';
import fs from 'fs/promises';

dotenv.config();
const POLYGON_RPC = process.env.POLYGON_RPC || 'https://polygon-rpc.com';
const POLYGONSCAN_API_KEY = process.env.POLYGONSCAN_API_KEY;


const HACK_TX = '0xe97e555d9423cf40a7ffe4dcf6a795067f7f133b89efc0f472650528ad8535ca';
const VICTIM_CONTRACT = '0x8B5Ea07B683953c82901E0f3Ad1dCC66cdD79568';
const HACKER_ADDRESS = '0x6d24389CEC21cd5437D5c581a40dAe6B336c9E5D';
const KNOWN_IMPLEMENTATION = '0x4660083D21e3A7e1eC5af8f46A31dCFAa78479Ed';

async function main() {
    try {
        if (!POLYGONSCAN_API_KEY) {
            throw new Error('POLYGONSCAN_API_KEY manquante dans le fichier .env');
        }
        console.log('Démarrage de l\'analyse du hack...');
        const web3 = new Web3(POLYGON_RPC);
        const analyzer = new SmartContractAnalyzer(POLYGON_RPC, POLYGONSCAN_API_KEY);
        const analysis = await analyzer.analyzeFromHack(HACK_TX, VICTIM_CONTRACT, HACKER_ADDRESS);
        await displayResults(analysis);
        await generateReports(analysis);

    } catch (error) {
        console.error('Erreur lors de l\'analyse:', error);
        process.exit(1);
    }
}

async function displayResults(analysis) {
    console.log('\n=== RÉSULTATS DE L\'ANALYSE ===');
    console.log('\n📄 Changements d\'implémentation:');
    if (analysis.hackDetails?.stateChanges) {
        const { before, after } = analysis.hackDetails.stateChanges;
        console.log('Avant:', before.implementation);
        console.log('Après:', after.implementation);
        
        if (before.implementation !== after.implementation) {
            console.log('⚠️  CHANGEMENT D\'IMPLÉMENTATION DÉTECTÉ!');
        }
    }
    if (analysis.suspiciousActions.length > 0) {
        console.log('\n🚨 Actions suspectes détectées:');
        analysis.suspiciousActions.forEach(action => {
            console.log(`- Transaction ${action.hash}`);
            console.log(`  De: ${action.from}`);
            console.log(`  À: ${action.to}`);
            console.log(`  Raison: ${action.reason.join(', ')}`);
        });
    }
    console.log('\n🔗 Contrats liés:');
    for (const contract of analysis.relatedContracts) {
        console.log(`- ${contract}`);
    }
    if (analysis.implementationHistory?.length > 0) {
        console.log('\n📚 Historique des implémentations:');
        analysis.implementationHistory.forEach(change => {
            console.log(`- Block ${change.blockNumber}: ${change.implementation}`);
        });
    }
}

async function generateReports(analysis) {
    const timestamp = Date.now();
    const jsonReport = {
        metadata: {
            analyzedAt: new Date().toISOString(),
            hackTransaction: HACK_TX,
            victimContract: VICTIM_CONTRACT,
            hackerAddress: HACKER_ADDRESS,
            knownImplementation: KNOWN_IMPLEMENTATION
        },
        analysis: analysis
    };

    let textReport = `RAPPORT D'ANALYSE DE HACK
=======================
Date d'analyse: ${new Date().toISOString()}

INFORMATIONS DE BASE
-------------------
Transaction de hack: ${HACK_TX}
Contrat victime: ${VICTIM_CONTRACT}
Adresse du hacker: ${HACKER_ADDRESS}
Implémentation connue: ${KNOWN_IMPLEMENTATION}

CHANGEMENTS D'ÉTAT
-----------------
${formatStateChanges(analysis.hackDetails?.stateChanges)}

ACTIONS SUSPECTES
----------------
${formatSuspiciousActions(analysis.suspiciousActions)}

CONTRATS IMPLIQUÉS
-----------------
${Array.from(analysis.relatedContracts).join('\n')}

HISTORIQUE DES IMPLÉMENTATIONS
---------------------------
${formatImplementationHistory(analysis.implementationHistory)}
`;

    await fs.writeFile(`hack_analysis_${timestamp}.json`, JSON.stringify(jsonReport, null, 2));
    await fs.writeFile(`hack_analysis_${timestamp}.txt`, textReport);

    console.log(`\n✅ Rapports générés:`);
    console.log(`- hack_analysis_${timestamp}.json`);
    console.log(`- hack_analysis_${timestamp}.txt`);
}

function formatStateChanges(stateChanges) {
    if (!stateChanges) return 'Aucun changement d\'état détecté';
    
    return `
Avant le hack:
- Implementation: ${stateChanges.before.implementation}
- Admin: ${stateChanges.before.admin}

Après le hack:
- Implementation: ${stateChanges.after.implementation}
- Admin: ${stateChanges.after.admin}
`;
}

function formatSuspiciousActions(actions) {
    if (!actions?.length) return 'Aucune action suspecte détectée';
    
    return actions.map(action => `
Transaction: ${action.hash}
De: ${action.from}
À: ${action.to}
Raison: ${action.reason.join(', ')}
Timestamp: ${action.timestamp}
`).join('\n');
}

function formatImplementationHistory(history) {
    if (!history?.length) return 'Aucun historique d\'implémentation disponible';
    
    return history.map(change => 
        `Block ${change.blockNumber}: ${change.implementation}`
    ).join('\n');
}



main().catch(console.error);
