import 'dotenv/config';
import { MongoClient } from 'mongodb';

const email = process.argv[2];

if (!email) {
    console.error('Usage: npm run make-admin -- <email>');
    process.exit(1);
}

if (!process.env.MONGODB_URI) {
    console.error('MONGODB_URI is missing from your .env file.');
    process.exit(1);
}

const client = new MongoClient(process.env.MONGODB_URI);

try {
    await client.connect();

    const users = client.db('web').collection('user');

    const result = await users.updateOne(
        { email: email.trim().toLowerCase() },
        {
            $set: {
                role: 'admin',
                isBlocked: false
            }
        }
    );

    if (result.matchedCount === 0) {
        console.error(`No user found with email ${email}. Sign up first.`);
        process.exitCode = 1;
    } else {
        console.log(`${email} is now an admin.`);
    }

} catch (error) {
    console.error('Failed to make admin:', error);
    process.exitCode = 1;
} finally {
    await client.close();
}
