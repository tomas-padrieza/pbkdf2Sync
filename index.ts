import { pbkdf2Sync, randomBytes } from 'node:crypto';
import KcAdminClient from '@keycloak/keycloak-admin-client';

const client = new KcAdminClient({ baseUrl: process.env.KC_BASE_URL });

async function authenticate() {
    const credentials = {
        grantType: 'password',
        clientId: 'admin-cli',
        username: process.env.KC_USERNAME,
        password: process.env.KC_PASSWORD,
    } as const;

    await client.auth(credentials);
}

async function updateUser({
    id,
    value,
    salt,
    hashIterations,
}: {
    id: string;
    value: string;
    salt: string;
    hashIterations: number;
}) {
    await client.users.update(
        { id, realm: 'demo' },
        {
            credentials: [
                {
                    type: 'password',
                    secretData: JSON.stringify({
                        value,
                        salt,
                    }),
                    credentialData: JSON.stringify({
                        algorithm: 'pbkdf2-sha512',
                        hashIterations,
                    }),
                    userLabel: 'new-password',
                    temporary: false,
                },
            ],
        }
    );

    console.log({
        type: 'password',
        secretData: JSON.stringify({
            value,
            salt,
        }),
        credentialData: JSON.stringify({
            algorithm: 'pbkdf2-sha512',
            hashIterations,
        }),
        userLabel: 'pbkdf2-sha512',
        temporary: false,
    });
}

async function main() {
    await authenticate();
    const [user] = await client.users.find({ realm: 'demo' });

    const password = 'NEW PASSWORD';
    const salt = randomBytes(16);
    const hashIterations = 10;

    const key = pbkdf2Sync(password, salt, hashIterations, 128, 'sha512');

    await updateUser({
        id: user.id!,
        value: key.toString('base64'),
        salt: salt.toString('base64'),
        hashIterations,
    });
}

main();
