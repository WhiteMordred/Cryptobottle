import Web3 from 'web3';
import fetch from 'node-fetch';
import fs from 'fs/promises';
import { saveToJson } from './save-utils.js';

class SmartContractAnalyzer {
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
        this.report = null;
    }

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
            await saveToJson(`${hackTxHash}_step1.json`, this.report);

            console.log(`\n📄 Analyse du contrat victime ${victimContract}...`);
            await this.analyzeVictimContract(victimContract);
            await saveToJson(`${hackTxHash}_step2.json`, this.report);

            console.log(`\n🕸️  Traçage des interactions entre contrats...`);
            await this.traceContractCalls(suspectAddress);
            await saveToJson(`${hackTxHash}_step3.json`, this.report);

            console.log(`\n📚 Analyse de l'historique d'implémentation...`);
            await this.analyzeImplementationHistory();
            await saveToJson(`${hackTxHash}_final.json`, this.report);

            return this.report;
        } catch (error) {
            console.error('Erreur lors de l\'analyse:', error);
            await saveToJson(`${hackTxHash}_error.json`, this.report);
            throw error;
        }
    }

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

    async getTransactionTraces(txHash) {
        const url = `${this.POLYGONSCAN_API}?module=account&action=txlistinternal&txhash=${txHash}&apikey=${this.apiKey}`;
        const response = await fetch(url);
        const data = await response.json();

        if (data.status === '1' && data.result) {
            return await this.analyzeTraces(data.result);
        }
        return [];
    }

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

    async analyzeVictimContract(contractAddress) {
        const code = await this.web3.eth.getCode(contractAddress);
        const isProxy = await this.isProxyContract(code);

        const transactions = await this.getContractTransactions(contractAddress);
        const analyzedTxs = await Promise.all(
            transactions.map(tx => this.analyzeSingleTransaction(tx))
        );

        this.report.victimAnalysis = {
            isProxy,
            codeHash: this.web3.utils.sha3(code),
            transactions: analyzedTxs.filter(tx => tx.suspicious)
        };
    }

    async getContractTransactions(address) {
        if (!this.isValidAddress(address)) {
            console.warn(`⚠️  Adresse de contrat invalide : "${address}".`);
            return [];
        }

        const url = `${this.POLYGONSCAN_API}?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${this.apiKey}`;
        const response = await fetch(url);
        const data = await response.json();

        if (data.status !== '1') return [];
        return data.result.filter(tx => this.isValidAddress(tx.from) && this.isValidAddress(tx.to));
    }

    async analyzeSingleTransaction(tx) {
        const analysis = {
            hash: tx.hash,
            from: tx.from,
            to: tx.to,
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

    async getContractState(address, blockNumber) {
        const implementation = await this.web3.eth.getStorageAt(address, this.STORAGE_SLOTS.IMPLEMENTATION, blockNumber);
        const admin = await this.web3.eth.getStorageAt(address, this.STORAGE_SLOTS.ADMIN, blockNumber);

        return {
            implementation: this.normalizeAddress(implementation),
            admin: this.normalizeAddress(admin)
        };
    }

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

    async isContract(address) {
        const code = await this.web3.eth.getCode(address);
        return code !== '0x';
    }

    isProxyContract(code) {
        return Object.values(this.FUNCTION_SIGNATURES).some(sig => code.includes(sig));
    }

    isSuspiciousCall(trace) {
        if (!trace.input || trace.input.length < 10) return false;
        return this.isSuspiciousSignature(trace.input.slice(0, 10));
    }

    isSuspiciousSignature(signature) {
        return [
            this.FUNCTION_SIGNATURES.UPGRADE_TO,
            this.FUNCTION_SIGNATURES.UPGRADE_TO_AND_CALL,
            this.FUNCTION_SIGNATURES.CHANGE_ADMIN
        ].includes(signature);
    }

    isValidAddress(address) {
        return this.web3.utils.isAddress(address) && address !== '0x0000000000000000000000000000000000000000';
    }

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

    getAbiByFunctionName(functionName) {
        const abiMapping = {
            UPGRADE_TO: [{ name: 'implementation', type: 'address' }],
            UPGRADE_TO_AND_CALL: [{ name: 'implementation', type: 'address' }, { name: 'data', type: 'bytes' }],
            CHANGE_ADMIN: [{ name: 'newAdmin', type: 'address' }],
            INITIALIZE: []
        };
        return abiMapping[functionName] || null;
    }

    normalizeAddress(hexData) {
        return this.web3.utils.toChecksumAddress('0x' + hexData.slice(-40));
    }
}

export default SmartContractAnalyzer;
