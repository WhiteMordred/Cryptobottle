// smart-contract-analyzer.js
import Web3 from 'web3';
import fetch from 'node-fetch';
import fs from 'fs/promises';

class SmartContractAnalyzer {
    /**
     * Constructeur de la classe SmartContractAnalyzer
     * @param {string} rpcUrl - URL du noeud Polygon RPC
     * @param {string} polygonscanApiKey - Cl  API de Polygonscan
     */
    constructor(rpcUrl, polygonscanApiKey) {
        this.web3 = new Web3(rpcUrl);
        this.apiKey = polygonscanApiKey;
        this.POLYGONSCAN_API = 'https://api.polygonscan.com/api';
        this.EVENT_SIGNATURES = {
            IMPLEMENTATION_CHANGED: '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b',
            ADMIN_CHANGED: '0x7e644d02266064d5d04a8737b839beb5a3f63eb0d7981dbc610fe9027e0569c8'
        };
        this.STORAGE_SLOTS = {
            IMPLEMENTATION: '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
            ADMIN: '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
            BEACON: '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'
        };
        this.FUNCTION_SIGNATURES = {
            UPGRADE_TO: '0x3659cfe6',
            UPGRADE_TO_AND_CALL: '0x4f1ef286',
            CHANGE_ADMIN: '0x8f283970',
            INITIALIZE: '0x8129fc1c'
        };
        this.processedContracts = new Set();
        this.contractInteractions = new Map();
        this.implementationChanges = [];
        this.suspiciousPatterns = [];
    }

    /**
     * Analyse une transaction de hack pour identifier les contrats impliqués et les opérations suspectes.
     * @param {string} hackTxHash - hash de la transaction de hack
     * @param {string} victimContract - adresse du contrat victime
     * @param {string} suspectAddress - adresse suspecte
     * @return {Promise<Object>} - rapport d'analyse
     */
    async analyzeFromHack(hackTxHash, victimContract, suspectAddress) {
        try {
            this.report = {
                hackTransaction: hackTxHash,
                victimContract,
                suspectAddress,
                startTime: new Date().toISOString(),
                implementations: [],
                contractCalls: [],
                proxyOperations: [],
                suspiciousActions: [],
                relatedContracts: new Set(),
                stateChanges: []
            };
            console.log(`\n🔍 Analyse de la transaction ${hackTxHash}...`);
            await this.analyzeHackTransaction(hackTxHash);
            console.log(`\n📄 Analyse du contrat victime ${victimContract}...`);
            await this.analyzeVictimContract(victimContract);
            console.log(`\n🕸️  Traçage des interactions entre contrats...`);
            await this.traceContractCalls(suspectAddress);
            console.log(`\n📚 Analyse de l'historique d'implémentation...`);
            await this.analyzeImplementationHistory();

            return this.report;
        } catch (error) {
            console.error('Erreur lors de l\'analyse:', error);
            throw error;
        }
    }

    /**
     * Analyse la transaction du hack pour extraire les informations pertinentes.
     * @param {string} txHash - Le hash de la transaction du hack.
     * @returns {Promise<void>}
     */
    async analyzeHackTransaction(txHash) {
        const tx = await this.web3.eth.getTransaction(txHash);
        const receipt = await this.web3.eth.getTransactionReceipt(txHash);
        const decodedLogs = await this.decodeLogs(receipt.logs);
        const traces = await this.getTransactionTraces(txHash);
        const blockNumber = Number(receipt.blockNumber);
        const stateChangesBefore = await this.getContractState(this.report.victimContract, blockNumber - 1);
        const stateChangesAfter = await this.getContractState(this.report.victimContract, blockNumber);

        this.report.hackDetails = {
            transaction: {
                ...tx,
                value: this.web3.utils.fromWei(tx.value.toString(), 'ether'),
                blockNumber: Number(tx.blockNumber),
                gas: Number(tx.gas),
                gasPrice: this.web3.utils.fromWei(tx.gasPrice.toString(), 'gwei')
            },
            receipt: {
                ...receipt,
                blockNumber: Number(receipt.blockNumber),
                gasUsed: Number(receipt.gasUsed)
            },
            logs: decodedLogs,
            traces: traces,
            stateChanges: {
                before: stateChangesBefore,
                after: stateChangesAfter
            }
        };
    }

    /**
     * Récupère les traces d'une transaction via l'API PolygonScan
     * @param {string} txHash - Le hash de la transaction
     * @returns {Object[]} Les traces de la transaction
     * @throws {Error} Si l'API renvoie une erreur
     */
    async getTransactionTraces(txHash) {
        const url = `${this.POLYGONSCAN_API}?module=account&action=txlistinternal&txhash=${txHash}&apikey=${this.apiKey}`;
        const response = await fetch(url);
        const data = await response.json();

        if (data.status === '1' && data.result) {
            return await this.analyzeTraces(data.result);
        }
        return [];
    }

    /**
     * Analyse les traces d'une transaction et les enrichit de
     * informations supplémentaires (type de appel, valeur, input, etc.)
     * @param {Object[]} traces - Les traces de la transaction
     * @returns {Object[]} Les traces enrichies
     */
    async analyzeTraces(traces) {
        const analyzedTraces = [];

        for (const trace of traces) {
            const isFromContract = await this.isContract(trace.from);
            const isToContract = await this.isContract(trace.to);

            if (isFromContract) this.report.relatedContracts.add(trace.from);
            if (isToContract) this.report.relatedContracts.add(trace.to);

            analyzedTraces.push({
                from: trace.from,
                to: trace.to,
                value: trace.value,
                input: trace.input,
                suspicious: this.isSuspiciousCall(trace),
                type: isFromContract ? (isToContract ? 'contract-to-contract' : 'contract-to-eoa')
                    : (isToContract ? 'eoa-to-contract' : 'eoa-to-eoa')
            });
        }

        return analyzedTraces;
    }

    /**
     * Décode les logs d'un contrat pour en extraire des informations utiles.
     * Les logs sont découpés en plusieurs types:
     *  - `implementation_change`: changement d'implémentation d'un contrat proxy.
     *    - `newImplementation`: l'adresse de l'implémentation qui a été mise à jour.
     *    - `blockNumber`: le numéro de bloc où la transaction a été minée.
     *    - `transactionHash`: le hash de la transaction qui a déclenché l'événement.
     *  - `admin_change`: changement d'administrateur d'un contrat proxy.
     *    - `previousAdmin`: l'adresse de l'administrateur précédent.
     *    - `newAdmin`: l'adresse de l'administrateur actuel.
     *    - `blockNumber`: le numéro de bloc où la transaction a été minée.
     *    - `transactionHash`: le hash de la transaction qui a déclenché l'événement.
     *  - `unknown`: log inconnu.
     *    - `signature`: la signature de l'événement.
     *    - `data`: les données de l'événement (pas décodées).
     *    - `topics`: les topics de l'événement.
     *    - `blockNumber`: le numéro de bloc où la transaction a été minée.
     *    - `transactionHash`: le hash de la transaction qui a déclenché l'événement.
     * @param {Object[]} logs les logs du contrat.
     * @return {Promise<Object[]>} les logs découpés en plusieurs types.
     */
    async decodeLogs(logs) {
        return Promise.all(logs.map(async log => {
            try {
                if (!log.topics[0]) return null;

                const signature = log.topics[0];
                let decodedLog = null;

                if (signature === this.EVENT_SIGNATURES.IMPLEMENTATION_CHANGED) {
                    decodedLog = {
                        type: 'implementation_change',
                        newImplementation: '0x' + log.topics[1]?.slice(26),
                        blockNumber: Number(log.blockNumber),
                        transactionHash: log.transactionHash
                    };
                } else if (signature === this.EVENT_SIGNATURES.ADMIN_CHANGED) {
                    try {
                        const params = this.web3.eth.abi.decodeParameters(
                            ['address', 'address'],
                            log.data
                        );
                        decodedLog = {
                            type: 'admin_change',
                            previousAdmin: params[0],
                            newAdmin: params[1],
                            blockNumber: Number(log.blockNumber),
                            transactionHash: log.transactionHash
                        };
                    } catch (error) {
                        console.warn('Erreur décodage admin change:', error);
                    }
                } else {
                    decodedLog = {
                        type: 'unknown',
                        signature,
                        data: log.data,
                        topics: log.topics,
                        blockNumber: Number(log.blockNumber),
                        transactionHash: log.transactionHash
                    };
                }

                return decodedLog;
            } catch (error) {
                console.warn(`Erreur lors du décodage du log:`, error);
                return null;
            }
        })).then(decodedLogs => decodedLogs.filter(log => log !== null));
    }

    /**
     * Analyse le contrat victime pour détecter des actions suspectes.
     * @param {string} contractAddress L'adresse du contrat victime
     * @returns {Promise<void>} Une promesse qui se résout lorsque l'analyse est terminée
     */
    async analyzeVictimContract(contractAddress) {
        // Récupérer le code du contrat
        const code = await this.web3.eth.getCode(contractAddress);
        const isProxy = await this.isProxyContract(code);

        // Récupérer l'historique des transactions
        const transactions = await this.getContractTransactions(contractAddress);

        // Analyser chaque transaction
        const analyzedTxs = await Promise.all(
            transactions.map(tx => this.analyzeSingleTransaction(tx))
        );

        // Mettre à jour le rapport
        this.report.victimAnalysis = {
            isProxy,
            codeHash: this.web3.utils.sha3(code),
            transactions: analyzedTxs.filter(tx => tx.suspicious)
        };
    }
    
    /**
     * Récupère l'historique des transactions d'un contrat.
     * @param {string} address L'adresse du contrat
     * @returns {Promise<Object[]>} Un tableau d'objets représentant les transactions.
     *
     * Chaque objet contient les clés suivantes:
     * - blockNumber: Le numéro du block
     * - timeStamp: Le timestamp de la transaction
     * - hash: Le hash de la transaction
     * - nonce: Le nonce de la transaction
     * - blockHash: Le hash du block
     * - from: L'adresse de l'expéditeur
     * - contractAddress: L'adresse du contrat
     * - to: L'adresse du destinataire
     * - value: La valeur de la transaction
     * - tokenName: Le nom du token (si applicable)
     * - tokenSymbol: Le symbole du token (si applicable)
     * - tokenDecimal: La décimale du token (si applicable)
     * - transactionIndex: L'index de la transaction dans le block
     * - gas: Le coût en gas de la transaction
     * - gasPrice: Le prix du gas en wei
     * - gasUsed: Le coût en gas de la transaction
     * - cumulativeGasUsed: Le coût en gas cumulé de toutes les transactions du block
     * - input: L'input de la transaction
     * - confirmations: Le nombre de confirmations
     */
    async getContractTransactions(address) {
        if (!this.isValidAddress(address)) {
            console.warn(`⚠️  Adresse de contrat invalide : "${address}".`);
            return [];
        }

        const url = `${this.POLYGONSCAN_API}?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${this.apiKey}`;
        const response = await fetch(url);
        const data = await response.json();

        if (data.status !== '1') return [];

        // Filtrer les transactions invalides
        return data.result.filter(tx => this.isValidAddress(tx.from) && this.isValidAddress(tx.to));
    }

    /**
     * Analyse une transaction isolée.
     * @param {Object} tx La transaction à analyser
     * @returns {Promise<Object>} Le résultat de l'analyse
     *
     * Les clés du résultat sont:
     * - hash: Le hash de la transaction
     * - from: L'adresse de l'expéditeur
     * - to: L'adresse du destinataire
     * - value: La valeur de la transaction
     * - input: L'input de la transaction
     * - timestamp: Le timestamp de la transaction
     * - suspicious: Un booléen indiquant si la transaction est suspecte
     * - reason: Un tableau de chaines indiquant les raisons de la suspicion
     */
    async analyzeSingleTransaction(tx) {
        const analysis = {
            hash: tx.hash,
            from: this.isValidAddress(tx.from) ? tx.from : 'Adresse invalide',
            to: this.isValidAddress(tx.to) ? tx.to : 'Adresse invalide',
            value: tx.value,
            input: tx.input,
            timestamp: new Date(parseInt(tx.timeStamp) * 1000).toISOString(),
            suspicious: false,
            reason: []
        };

        if (tx.input && tx.input.length >= 10) {
            const signature = tx.input.slice(0, 10);
            const decodedInput = await this.decodeTransactionInput(tx.input);
            analysis.decodedInput = decodedInput;

            if (this.isSuspiciousSignature(signature)) {
                analysis.suspicious = true;
                analysis.reason.push('suspicious_signature');
            }
        }

        return analysis;
    }

    /**
     * Récupère l'historique des implémentations du contrat cible.
     * @returns {Promise<void>} - Met à jour le rapport avec l'historique des implémentations
     */
    async analyzeImplementationHistory() {
        const implementations = [];
        let currentBlock = 0;
        const latestBlock = await this.web3.eth.getBlockNumber();

        while (currentBlock < latestBlock) {
            const impl = await this.getImplementationAt(this.report.victimContract, currentBlock);
            if (impl) {
                implementations.push({
                    blockNumber: currentBlock,
                    implementation: impl
                });
            }
            currentBlock += 1000;
        }

        this.report.implementationHistory = implementations;
    }

    /**
     * Récupère l'état du contrat à un bloc donné.
     * @param {string} address - L'adresse du contrat
     * @param {number} blockNumber - Le numéro de bloc
     * @returns {Promise<{implementation: string, admin: string}>} - L'état du contrat {implementation, admin}
     */
    async getContractState(address, blockNumber) {
        const implementation = await this.web3.eth.getStorageAt(
            address,
            this.STORAGE_SLOTS.IMPLEMENTATION,
            blockNumber
        );
        const admin = await this.web3.eth.getStorageAt(
            address,
            this.STORAGE_SLOTS.ADMIN,
            blockNumber
        );

        return {
            implementation: this.normalizeAddress(implementation),
            admin: this.normalizeAddress(admin)
        };
    }


    /**
     * Détermine si l'adresse donnée correspond à un contrat.
     * Une adresse est considérée comme un contrat si son code est non vide.
     * @param {string} address - L'adresse à vérifier
     * @returns {Promise<boolean>} Si l'adresse est un contrat
     */
    async isContract(address) {
        if (!this.isValidAddress(address)) {
            console.warn(`⚠️  Adresse non valide passée à isContract : "${address}".`);
            return false;
        }
        const code = await this.web3.eth.getCode(address);
        return code !== '0x';
    }

    /**
     * Détermine si un code de contrat est un contrat proxy.
     * Un contrat est considéré comme proxy si son code contient l'une des signatures de fonction
     * définies dans {@link FUNCTION_SIGNATURES}.
     * @param {string} code - Le code du contrat à analyser
     * @returns {Promise<boolean>} Si le contrat est un contrat proxy
     */
    async isProxyContract(code) {
        return Object.values(this.FUNCTION_SIGNATURES)
            .some(sig => code.includes(sig));
    }

    isSuspiciousCall(trace) {
        if (!trace.input || trace.input.length < 10) return false;
        return this.isSuspiciousSignature(trace.input.slice(0, 10));
    }


    /**
     * Détermine si la signature de fonction donnée correspond à une appel suspect.
     * Les appels suspects sont actuellement :
     * - l'appel à la méthode d'upgrade d'implémentation
     * - l'appel à la méthode d'upgrade d'implémentation avec appel à un contrat
     * - l'appel à la méthode de changement d'administrateur
     * @param {string} signature - La signature de la fonction à analyser
     * @return {boolean} Si la signature est suspecte
     */
    isSuspiciousSignature(signature) {
        return [
            this.FUNCTION_SIGNATURES.UPGRADE_TO,
            this.FUNCTION_SIGNATURES.UPGRADE_TO_AND_CALL,
            this.FUNCTION_SIGNATURES.CHANGE_ADMIN
        ].includes(signature);
    }

    /**
     * Récupère l'implémentation du contrat à un block spécifique.
     * @param {string} contractAddress Adresse du contrat à analyser
     * @param {number} blockNumber Block à partir duquel récupérer l'implémentation
     * @returns {string|null} Adresse de l'implémentation ou null si erreur
     */
    async getImplementationAt(contractAddress, blockNumber) {
        try {
            const storageValue = await this.web3.eth.getStorageAt(
                contractAddress,
                this.STORAGE_SLOTS.IMPLEMENTATION,
                blockNumber
            );
            if (storageValue && storageValue !== '0x0000000000000000000000000000000000000000') {
                return this.normalizeAddress(storageValue);
            }

            return null;
        } catch (error) {
            console.warn(`Erreur lors de la récupération de l'implémentation au block ${blockNumber}:`, error);
            return null;
        }
    }
    
    normalizeAddress(hexData) {
        return this.web3.utils.toChecksumAddress('0x' + hexData.slice(-40));
    }

    /**
     * Suivi des appels entre les contrats.
     * Parcourt l'historique des transactions de chaque contrat et ajoute les contrats ciblés à un ensemble.
     * Pour chaque transaction, analyse si elle est suspecte et l'ajoute à un tableau.
     * @param {string} startAddress Adresse du contrat de départ
     */
    async traceContractCalls(startAddress) {
        const contractsToAnalyze = new Set([startAddress]);

        for (const contract of contractsToAnalyze) {
            if (!this.isValidAddress(contract)) {
                console.warn(`⚠️  Adresse invalide détectée : "${contract}". Ignoré.`);
                continue;
            }

            if (this.processedContracts.has(contract)) continue;
            this.processedContracts.add(contract);

            const transactions = await this.getContractTransactions(contract);
            for (const tx of transactions) {
                if (tx.to && this.isValidAddress(tx.to) && await this.isContract(tx.to)) {
                    contractsToAnalyze.add(tx.to);
                }

                const analysis = await this.analyzeSingleTransaction(tx);
                if (analysis.suspicious) {
                    this.report.suspiciousActions.push(analysis);
                }
            }
        }
    }

    /**
     * Vérifie si l'adresse est valide.
     * Une adresse est considérée comme valide si elle est une adresse Ethereum
     * et qu'elle n'est pas l'adresse zéro.
     * @param {string} address - L'adresse à vérifier.
     * @returns {boolean} Vrai si l'adresse est valide, faux sinon.
     */
    isValidAddress(address) {
        return this.web3.utils.isAddress(address) && address !== '0x0000000000000000000000000000000000000000';
    }

    /**
     * Décode un input de transaction en une méthode et ses paramètres.
     * @param {string} inputData - Les données de l'input de la transaction.
     * @returns {Object} Un objet contenant le nom de la méthode et ses paramètres décodés.
     * @property {string} method - Le nom de la méthode.
     * @property {Object} params - Les paramètres décodés.
     */
    decodeTransactionInput(inputData) {
        if (!inputData || inputData.length < 10) return { method: 'unknown', params: {} };
    
        const functionSignature = inputData.slice(0, 10);
        const method = Object.entries(this.FUNCTION_SIGNATURES).find(([_, sig]) => sig === functionSignature);
    
        if (!method) {
            return { method: 'unknown', params: {} };
        }
    
        const functionName = method[0];
        const paramsAbi = this.getAbiByFunctionName(functionName);
    
        if (!paramsAbi || !paramsAbi.length) {
            return { method: functionName, params: {} };
        }
    
        try {
            const decodedParams = this.web3.eth.abi.decodeParameters(paramsAbi, inputData.slice(10));
            return { method: functionName, params: decodedParams };
        } catch (error) {
            console.warn(`Erreur lors du décodage des paramètres pour la fonction ${functionName}:`, error);
            return { method: functionName, params: {} };
        }
    }


    /**
     * Retourne l'ABI correspondant à une fonction donnée.
     * @param {string} functionName - Le nom de la fonction.
     * @returns {Object[]} L'ABI de la fonction.
     */
    getAbiByFunctionName(functionName) {
        const abiMapping = {
            UPGRADE_TO: [{ name: 'implementation', type: 'address' }],
            UPGRADE_TO_AND_CALL: [
                { name: 'implementation', type: 'address' },
                { name: 'data', type: 'bytes' }
            ],
            CHANGE_ADMIN: [{ name: 'newAdmin', type: 'address' }],
            INITIALIZE: [] 
        };
        return abiMapping[functionName] || null;
    }


}

export default SmartContractAnalyzer;
