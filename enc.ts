import { pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'fs';
import ProgressBar from 'progress';

const hashIterations = 10;
const enc = (password: string, salt: Buffer) =>
    pbkdf2Sync(password, salt, hashIterations, 128, 'sha512').toString('base64');

function main() {
    const csv = readFileSync('csv/mock_data.csv').toString();
    const [header, ...records] = csv.split('\n');

    const users = records.filter((rec) => rec.trim() !== '');

    const bar = new ProgressBar('-> Processing [:current/:total] [:bar] :percent :elapsed', {
        total: users.length,
        width: 30,
    });

    const entries = users.map((rec) => {
        const [userName, firstName, lastName, ...password] = rec.split(',');

        const salt = randomBytes(16);
        const encPass = enc(password.join(''), salt);
        bar.tick(1);

        return `${userName},${firstName},${lastName},${encPass},${salt.toString('base64')}`;
    });

    writeFileSync('csv/enc_data.csv', `${header},salt\n${entries.join('\n')}`, { flag: 'w+' });
}

main();
