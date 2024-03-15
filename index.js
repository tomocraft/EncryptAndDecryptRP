const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const readline = require("readline");
const colors = require("colors");
const { glob } = require("glob");
const JSZip = require('jszip');

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
const algorithm = "aes-256-cfb8";
const excludeFiles = ["manifest.json", "pack_icon.png", "bug_pack_icon.png"];
let processedFiles = 0;

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const usageText = `
  < Command Usage >
   - encrypt <inputFolder> <outputFolder> <key(optional)>
      - Encrypt Resource Pack
   - decrypt <key> <targetFolder> <outputFolder>
      - Decrypt Resource Pack
   - stop | [ Ctrl + C ]
      - Stop Process
`;

console.log(
    colors.green.bold(usageText)
);

async function processUserInput(input) {
    function wrongCommand() {
        console.warn("Please Enter Correct Command!\n");
    }
    const [command, ...args] = input.split(" ");
    switch (command) {
        case "encrypt":
            if (args.length === 2 || args.length === 3) {
                const inputFolder = args[0];
                const outputFolder = args[1];
                const key = args[2] ? args[2] : null;
                await encrypt(inputFolder, outputFolder, key);
                console.log("\n");
            } else {
                wrongCommand();
            }
            break;
        case "decrypt":
            if (args.length === 3) {
                const key = args[0];
                const targetFolder = args[1];
                const outputFolder = args[2];
                await decrypt(key, targetFolder, outputFolder);
                console.log("\n");
            } else {
                wrongCommand();
            }
            break;
        case "stop":
            rl.close();
            console.log("Stop Process...");
            process.exit();
        default:
            wrongCommand();
            break;
    }
    rl.question("Command: ", processUserInput);
}

rl.question("Command: ", processUserInput);

process.on('beforeExit', () => {
    rl.pause();
    rl.close();
    console.log('\nStop Process...');
    process.exit(0);
});

function randomString(length) {
    let result = '';
    for (let i = 0; i < length; i++) {
        result += letters.charAt(Math.floor(Math.random() * letters.length));
    }
    return result;
}

function generateKey() {
    const key = randomString(32);
    const iv = key.slice(0, 16);
    return { key: Buffer.from(key), iv: Buffer.from(iv) };
}

function progressBar(progress) {
    const barLength = 50;
    const filledLength = Math.round(barLength * progress);
    const bar = '█'.repeat(filledLength) + '-'.repeat(barLength - filledLength);
    const percentage = Math.round(progress * 100);
    process.stdout.clearLine();
    process.stdout.cursorTo(0);
    process.stdout.write(`[${bar}] ${percentage}%`);
    if (progress === 1) {
        process.stdout.write('\n');
    }
}

function addProgress(files) {
    processedFiles++;
    const progress = processedFiles / files.length;
    progressBar(progress);
}

async function encrypt(input, output, specifiedKey) {
    const inputPath = path.resolve(input);
    const outputPath = path.resolve(output);
    const contentEntries = [];
    let uuid;
    if (specifiedKey && !/^[a-zA-Z0-9]{32}$/.test(specifiedKey)) {
        return console.log('Encryption key must be 32 characters long and contain only alphanumeric characters.');
    }
    try {
        const stats = fs.statSync(inputPath);
        if (stats.isDirectory()) {
            if (inputPath === outputPath) {
                return console.log("You can\'t specify same folder!");
            }
            if (!outputPath.startsWith(path.dirname(outputPath))) {
                return console.log("You can only specify a path within this directory!");
            }
            if (fs.existsSync(outputPath)) {
                await fs.promises.rm(outputPath, { recursive: true });
            }
            await fs.promises.mkdir(path.dirname(outputPath), { recursive: true });
            uuid = JSON.parse(await fs.promises.readFile(path.join(inputPath, "manifest.json"), { encoding: "utf8" })).header.uuid;
            const files = await glob(`${inputPath}/**/*`);
            processedFiles = 0;
            for (const inputEntryPath of files) {
                if (!(await fs.promises.stat(inputEntryPath)).isFile()) {
                    addProgress(files);
                    continue;
                }
                const relativePath = path.relative(inputPath, inputEntryPath).replace(/\\/g, "/");
                const outputEntryPath = path.join(outputPath, relativePath);
                await fs.promises.mkdir(path.dirname(outputEntryPath), { recursive: true });
                if (excludeFiles.includes(relativePath)) {
                    if (inputEntryPath !== outputEntryPath) {
                        if (relativePath.endsWith(".json")) {
                            try {
                                const value = JSON.parse(await fs.promises.readFile(inputEntryPath, { encoding: "utf8" }));
                                await fs.promises.writeFile(outputEntryPath, JSON.stringify(value, null, 4));
                            } catch (e) {
                                await fs.promises.copyFile(inputEntryPath, outputEntryPath);
                            }
                        } else {
                            await fs.promises.copyFile(inputEntryPath, outputEntryPath);
                        }
                    }
                    contentEntries.push({ path: relativePath, key: null });
                } else {
                    const { key, iv } = generateKey();
                    const fileContent = await fs.promises.readFile(inputEntryPath);
                    const cipher = crypto.createCipheriv(algorithm, key, iv);
                    const encryptedContent = cipher.update(fileContent);
                    await fs.promises.writeFile(outputEntryPath, encryptedContent);
                    contentEntries.push({ path: relativePath, key: key.toString() });
                }
                addProgress(files);
            }
            const content = { content: contentEntries };
            const contentBuffer = Buffer.from(JSON.stringify(content));
            let { key, iv } = generateKey();
            if (specifiedKey) {
                key = Buffer.from(specifiedKey);
                iv = key.slice(0, 16);
            }
            const cipher = crypto.createCipheriv(algorithm, key, iv);
            const encryptedContentData = cipher.update(contentBuffer);
            const encryptedContentBuffer = Buffer.from(encryptedContentData);
            const version = Buffer.from([0x00, 0x00, 0x00, 0x00]);
            const magic = Buffer.from([0xFC, 0xB9, 0xCF, 0x9B]);
            const null_8 = Buffer.alloc(8);
            const id_length = Buffer.from([0x24]);
            const id = Buffer.from(uuid);
            const zeroBytes = Buffer.alloc(203);
            const contentData = Buffer.concat([version, magic, null_8, id_length, id, zeroBytes, encryptedContentBuffer]);
            await fs.promises.writeFile(path.join(outputPath, "contents.json"), contentData);
            console.log(`Encryption Complete! Encryption Key: ${key.toString()}`);
        } else {
            if (!outputPath.startsWith(path.dirname(outputPath))) {
                return console.log("You can only specify a path within this directory!");
            }
            const fileContent = await fs.promises.readFile(inputPath);
            const zip = new JSZip();
            const encryptedZip = new JSZip();
            await zip.loadAsync(fileContent);
            let relativePath;
            processedFiles = 0;
            let filesLength = { length: 0 };
            for (const fileName in zip.files) {
                if (fileName.endsWith('manifest.json')) {
                    relativePath = fileName.slice(0, fileName.lastIndexOf('manifest.json'));
                    const file = zip.files[fileName];
                    const rawJson = await file.async('text');
                    const formattedJson = JSON.parse(rawJson);
                    uuid = formattedJson.header.uuid;
                }
                filesLength.length++;
            }
            for (const fileName in zip.files) {
                const file = zip.files[fileName];
                if (file.dir) {
                    encryptedZip.folder(fileName);
                } else if (
                    !fileName.endsWith('manifest.json') &&
                    !fileName.endsWith('pack_icon.png') &&
                    !fileName.endsWith('bug_pack_icon.png')
                ) {
                    const content = await file.async('nodebuffer');
                    const { key, iv } = generateKey();
                    const cipher = crypto.createCipheriv(algorithm, key, iv);
                    const encryptedContent = cipher.update(content);
                    encryptedZip.file(fileName, encryptedContent);
                    contentEntries.push({ path: fileName.slice(relativePath.length), key: key });
                } else {
                    const content = await file.async('nodebuffer');
                    encryptedZip.file(fileName, content);
                }
                addProgress(filesLength);
            }
            const content = { content: contentEntries };
            const contentBuffer = Buffer.from(JSON.stringify(content));
            let { key, iv } = generateKey();
            if (specifiedKey) {
                key = Buffer.from(specifiedKey);
                iv = key.slice(0, 16);
            }
            const cipher = crypto.createCipheriv(algorithm, key, iv);
            const encryptedContentData = cipher.update(contentBuffer);
            const encryptedContentBuffer = Buffer.from(encryptedContentData);
            const version = Buffer.from([0x00, 0x00, 0x00, 0x00]);
            const magic = Buffer.from([0xFC, 0xB9, 0xCF, 0x9B]);
            const null_8 = Buffer.alloc(8);
            const id_length = Buffer.from([0x24]);
            const id = Buffer.from(uuid);
            const zeroBytes = Buffer.alloc(203);
            const contentData = Buffer.concat([version, magic, null_8, id_length, id, zeroBytes, encryptedContentBuffer]);
            encryptedZip.file(relativePath + 'contents.json', contentData);
            await encryptedZip.generateAsync({ type: 'nodebuffer' })
                .then(async (buffer) => {
                    let formattedOutputPath = outputPath;
                    if (
                        !outputPath.endsWith('.zip') &&
                        !outputPath.endsWith('.mcpack') &&
                        !outputPath.endsWith('.mcaddon')
                    ) {
                        formattedOutputPath = formattedOutputPath + '.zip';
                    }
                    await fs.promises.writeFile(formattedOutputPath, buffer);
                    console.log(`Encryption Complete! Encryption Key: ${key.toString()}`);
                });
        }
    } catch (e) {
        console.error(`An error occurred during encrypting the resource pack!\nError: ${e.message}`);
    }
}

async function decrypt(key, target, output) {
    const keyBuffer = Buffer.from(key);
    const targetPath = path.resolve(target);
    const outputPath = path.resolve(output);
    const iv = keyBuffer.slice(0, 16);
    if (!/^[a-zA-Z0-9]{32}$/.test(key)) {
        console.warn(`Probably ${key} is not a encryption key.`);
    }
    try {
        const stats = fs.statSync(targetPath);
        if (stats.isDirectory()) {
            if (targetPath === outputPath) {
                return console.log("You can\'t specify same folder!");
            }
            if (!outputPath.startsWith(path.dirname(outputPath))) {
                return console.log("You can only specify a path within this directory!");
            }
            if (fs.existsSync(outputPath)) {
                await fs.promises.rm(outputPath, { recursive: true });
            }
            await fs.promises.mkdir(path.dirname(outputPath), { recursive: true });
            const contentsRaw = Buffer.from(await fs.promises.readFile(path.join(targetPath, "contents.json")));
            const contentBody = contentsRaw.slice(0x100);
            const decryptedContent = Buffer.from(crypto.createDecipheriv(algorithm, keyBuffer, iv).update(contentBody)).toString();
            const contentsJson = JSON.parse(decryptedContent);
            const pathToKeyMap = new Map();
            contentsJson.content.forEach(element => {
                pathToKeyMap.set(element.path, element.key);
            });
            const files = await glob(`${targetPath}/**/*`);
            processedFiles = 0;
            for (const targetEntryPath of files) {
                if (!(await fs.promises.stat(targetEntryPath)).isFile()) {
                    addProgress(files);
                    continue;
                }
                const relativePath = path.relative(targetPath, targetEntryPath).replace(/\\/g, "/");
                const outputEntryPath = path.join(outputPath, relativePath);
                await fs.promises.mkdir(path.dirname(outputEntryPath), { recursive: true });
                if (excludeFiles.includes(relativePath) || ("contents.json").includes(relativePath)) {
                    if (targetEntryPath !== outputEntryPath) {
                        if (("contents.json").includes(relativePath)) {
                            addProgress(files);
                            continue;
                        }
                        if (relativePath.endsWith(".json")) {
                            try {
                                const value = JSON.parse(await fs.promises.readFile(targetEntryPath, { encoding: "utf8" }));
                                await fs.promises.writeFile(outputEntryPath, JSON.stringify(value, null, 4));
                            } catch (e) {
                                await fs.promises.copyFile(targetEntryPath, outputEntryPath);
                            }
                        } else {
                            await fs.promises.copyFile(targetEntryPath, outputEntryPath);
                        }
                    }
                } else {
                    const key = Buffer.from(pathToKeyMap.get(relativePath));
                    const iv = key.slice(0, 16);
                    const fileContent = await fs.promises.readFile(targetEntryPath);
                    const cipher = crypto.createDecipheriv(algorithm, key, iv);
                    const encryptedContent = cipher.update(fileContent);
                    await fs.promises.writeFile(outputEntryPath, encryptedContent);
                }
                addProgress(files);
            }
            console.log(`Decryption Complete!`);
        } else {
            if (!outputPath.startsWith(path.dirname(outputPath))) {
                return console.log("You can only specify a path within this directory!");
            }
            const fileContent = await fs.promises.readFile(targetPath);
            const zip = new JSZip();
            const decryptedZip = new JSZip();
            await zip.loadAsync(fileContent);
            let relativePath;
            const pathToKeyMap = new Map();
            processedFiles = 0;
            let filesLength = { length: 0 };
            for (const fileName in zip.files) {
                if (fileName.endsWith('contents.json')) {
                    relativePath = fileName.slice(0, fileName.lastIndexOf('contents.json'));
                    const file = zip.files[fileName];
                    const rawContent = await file.async('nodebuffer');
                    const slicedContent = rawContent.slice(0x100);
                    const decryptedContent = Buffer.from(crypto.createDecipheriv(algorithm, keyBuffer, iv).update(slicedContent)).toString();
                    const contentsJson = JSON.parse(decryptedContent);
                    contentsJson.content.forEach(element => {
                        pathToKeyMap.set(element.path, Buffer.from(element.key));
                    });
                }
                filesLength.length++;
            }
            for (const fileName in zip.files) {
                const file = zip.files[fileName];
                if (file.dir) {
                    decryptedZip.folder(fileName);
                } else if (
                    !fileName.endsWith('manifest.json') &&
                    !fileName.endsWith('pack_icon.png') &&
                    !fileName.endsWith('bug_pack_icon.png') &&
                    !fileName.endsWith('contents.json')
                ) {
                    const content = await file.async('nodebuffer');
                    const key = pathToKeyMap.get(fileName.slice(relativePath.length));
                    const iv = key.slice(0, 16);
                    const cipher = crypto.createDecipheriv(algorithm, key, iv);
                    const encryptedContent = cipher.update(content);
                    decryptedZip.file(fileName, encryptedContent);
                } else if (fileName.endsWith('contents.json')) {
                    addProgress(filesLength);
                    continue;
                } else {
                    const content = await file.async('nodebuffer');
                    decryptedZip.file(fileName, content);
                }
                addProgress(filesLength);
            }
            await decryptedZip.generateAsync({ type: 'nodebuffer' })
                .then(async (buffer) => {
                    let formattedOutputPath = outputPath;
                    if (
                        !outputPath.endsWith('.zip') &&
                        !outputPath.endsWith('.mcpack') &&
                        !outputPath.endsWith('.mcaddon')
                    ) {
                        formattedOutputPath = formattedOutputPath + '.zip';
                    }
                    await fs.promises.writeFile(formattedOutputPath, buffer);
                    console.log(`Decryption Complete!`);
                });
        }
    } catch (e) {
        console.error(`An error occurred during decrypting the resource pack!\nError: ${e.message}`);
    }
}