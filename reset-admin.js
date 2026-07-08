require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const MONGODB_URI = process.env.MONGODB_URI;
const SALT_ROUNDS = 12;

if (!MONGODB_URI) {
  console.error('Missing MONGODB_URI in .env');
  process.exit(1);
}

const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true, lowercase: true, trim: true, index: true },
    password: String,
    role: String,
    isActive: Boolean
  },
  { collection: 'users' }
);

const User = mongoose.model('User', userSchema);

async function main() {
  const email = 'admin@example.com';
  const newPassword = 'NewAdmin@12345';

  try {
    await mongoose.connect(MONGODB_URI, { dbName: 'financial_suite' });

    const hashed = await bcrypt.hash(newPassword, SALT_ROUNDS);

    const result = await User.updateOne(
      { email },
      {
        $set: {
          name: 'Admin User',
          email,
          password: hashed,
          role: 'admin',
          isActive: true
        }
      },
      { upsert: true }
    );

    console.log('Matched:', result.matchedCount);
    console.log('Modified:', result.modifiedCount);
    console.log('Upserted:', result.upsertedCount || 0);
    console.log(`Admin reset complete for ${email}`);

    await mongoose.disconnect();
    process.exit(0);
  } catch (error) {
    console.error('Reset failed:', error);
    try { await mongoose.disconnect(); } catch {}
    process.exit(1);
  }
}

main();
