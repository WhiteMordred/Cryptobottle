// analyze_hack.js
import SmartContractAnalyzer from './smart-contract-analyzer.js';
import Web3 from 'web3';
import dotenv from 'dotenv';
import fs from 'fs/promises';
import path from 'path';

dotenv.config();

const RPC_NODES = [
    process.env.POLYGON_RPC || 'https://polygon-rpc.com',
    'https://rpc-mainnet.maticvigil.com',
    'https://polygon-rpc.com'
];

const POLYGONSCAN_API_KEY = process.env.POLYGONSCAN_API_KEY;
const ANALYSIS_DIR = './analysis_output';

const HACK_TX = '0xe97e555d9423cf40a7ffe4dcf6a795067f7f133b89efc0f472650528ad8535ca';
const VICTIM_CONTRACT = '0x8B5Ea07B683953c82901E0f3Ad1dCC66cdD79568';
const HACKER_ADDRESS = '0x6d24389CEC21cd5437D5c581a40dAe6B336c9E5D';
const KNOWN_IMPLEMENTATION = '0x4660083D21e3A7e1eC5af8f46A31dCFAa78479Ed';

async function initAnalysis() {
    if (!POLYGONSCAN_API_KEY) {
        throw new Error('POLYGONSCAN_API_KEY manquante dans le fichier .env');
    }
    await fs.mkdir(ANALYSIS_DIR, { recursive: true });
}

async function tryWithDifferentRPC(analysisFunction) {
    for (let i = 0; i < RPC_NODES.length; i++) {
        try {
            console.log(`\nTentative avec RPC ${i + 1}/${RPC_NODES.length}...`);
            const web3 = new Web3(RPC_NODES[i]);
            const analyzer = new SmartContractAnalyzer(RPC_NODES[i], POLYGONSCAN_API_KEY);
            return await analysisFunction(analyzer);
        } catch (error) {
            console.error(`Erreur avec RPC ${i + 1}:`, error.message);
            if (i === RPC_NODES.length - 1) throw error;
            console.log('Tentative avec le prochain RPC...');
        }
    }
}

async function main() {
    try {
        await initAnalysis();
        console.log('🔍 Démarrage de l\'analyse du hack...');

        const analysis = await tryWithDifferentRPC(async (analyzer) => {
            return await analyzer.analyzeFromHack(HACK_TX, VICTIM_CONTRACT, HACKER_ADDRESS);
        });

        await displayResults(analysis);
        await generateReports(analysis);

    } catch (error) {
        console.error('❌ Erreur finale lors de l\'analyse:', error);
        process.exit(1);
    }
}

async function displayResults(analysis) {
    console.log('\n=== RÉSULTATS DE L\'ANALYSE ===');

    if (analysis.hackDetails?.stateChanges) {
        console.log('\n📄 Changements d\'état détectés:');
        const { before, after } = analysis.hackDetails.stateChanges;
        console.log('État initial:');
        console.log('- Implementation:', before.implementation);
        console.log('- Admin:', before.admin);
        console.log('\nÉtat après hack:');
        console.log('- Implementation:', after.implementation);
        console.log('- Admin:', after.admin);

        if (before.implementation !== after.implementation) {
            console.log('\n⚠️  CHANGEMENT D\'IMPLÉMENTATION DÉTECTÉ!');
        }
        if (before.admin !== after.admin) {
            console.log('\n⚠️  CHANGEMENT D\'ADMIN DÉTECTÉ!');
        }
    }

    if (analysis.suspiciousActions?.length > 0) {
        console.log('\n🚨 Actions suspectes détectées:');
        analysis.suspiciousActions.forEach((action, index) => {
            console.log(`\nAction suspecte #${index + 1}:`);
            console.log(`- Transaction: ${action.hash}`);
            console.log(`- De: ${action.from}`);
            console.log(`- À: ${action.to}`);
            console.log(`- Raison: ${action.reason.join(', ')}`);
            if (action.decodedInput?.method) {
                console.log(`- Méthode: ${action.decodedInput.method}`);
            }
            console.log(`- Timestamp: ${action.timestamp}`);
        });
    }

    if (analysis.relatedContracts?.size > 0) {
        console.log('\n🔗 Contrats impliqués:');
        for (const contract of analysis.relatedContracts) {
            console.log(`- ${contract}`);
        }
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
    
    const reportData = {
        metadata: {
            analyzedAt: new Date().toISOString(),
            hackTransaction: HACK_TX,
            victimContract: VICTIM_CONTRACT,
            hackerAddress: HACKER_ADDRESS,
            knownImplementation: KNOWN_IMPLEMENTATION
        },
        analysis: {
            ...analysis,
            relatedContracts: Array.from(analysis.relatedContracts || [])
        }
    };

    const safeData = JSON.stringify(reportData, (key, value) => 
        typeof value === 'bigint' ? value.toString() : value, 2);

    const textReport = `
RAPPORT D'ANALYSE DE HACK
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
Avant le hack:
- Implementation: ${analysis.hackDetails?.stateChanges?.before?.implementation}
- Admin: ${analysis.hackDetails?.stateChanges?.before?.admin}

Après le hack:
- Implementation: ${analysis.hackDetails?.stateChanges?.after?.implementation}
- Admin: ${analysis.hackDetails?.stateChanges?.after?.admin}

ACTIONS SUSPECTES
----------------
${analysis.suspiciousActions?.map(action => `
Transaction: ${action.hash}
De: ${action.from}
À: ${action.to}
Raison: ${action.reason.join(', ')}
Méthode: ${action.decodedInput?.method || 'N/A'}
Timestamp: ${action.timestamp}
`).join('\n') || 'Aucune action suspecte détectée'}

CONTRATS IMPLIQUÉS
-----------------
${Array.from(analysis.relatedContracts || []).join('\n') || 'Aucun contrat impliqué'}

HISTORIQUE DES IMPLÉMENTATIONS
---------------------------
${analysis.implementationHistory?.map(change => `Block ${change.blockNumber}: ${change.implementation}`).join('\n') || 'Pas d\'historique d\'implémentation'}
`;

    const jsonPath = path.join(ANALYSIS_DIR, `analysis_${timestamp}.json`);
    const textPath = path.join(ANALYSIS_DIR, `analysis_${timestamp}.txt`);

    await fs.writeFile(jsonPath, safeData);
    await fs.writeFile(textPath, textReport);

    console.log(`\n✅ Rapports générés avec succès:`);
    console.log(`- ${jsonPath}`);
    console.log(`- ${textPath}`);
}

main().catch(error => {
    console.error('❌ Erreur critique:', error);
    process.exit(1);
});
