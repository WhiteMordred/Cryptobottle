import fs from 'fs/promises';
import path from 'path';

/**
 * Sauvegarde les données dans un fichier JSON
 * @param {string} prefix - Préfixe pour le nom du fichier
 * @param {Object} data - Données à sauvegarder
 */
export async function saveToJson(prefix, data) {
    try {
        await fs.mkdir('./analysis_data', { recursive: true });
        const safeData = JSON.stringify(data, (key, value) => {
            if (typeof value === 'bigint') return value.toString();
            if (value instanceof Set) return Array.from(value);
            return value;
        }, 2);

        const filename = path.join('./analysis_data', `${prefix}_${Date.now()}.json`);
        await fs.writeFile(filename, safeData);
        console.log(`✅ Données sauvegardées dans ${filename}`);
    } catch (error) {
        console.error('❌ Erreur lors de la sauvegarde:', error);
    }
}
