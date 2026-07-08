require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/financial_suite';
const SALT_ROUNDS = 12;

const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true, lowercase: true, trim: true },
    password: String,
    role: String,
    isActive: Boolean
  },
  { collection: 'users' }
);

const User = mongoose.model('User', userSchema);

async function resetPassword() {
  const email = 'admin@example.com';
  const newPassword = 'NewAdmin@12345'; // change if you want

  try {
    await mongoose.connect(MONGODB_URI, { dbName: 'financial_suite' });

    const hashed = await bcrypt.hash(newPassword, SALT_ROUNDS);

    const result = await User.updateOne(
      { email },
      {
        $set: {
          password: hashed,
          isActive: true,
          role: 'admin',
          name: 'Admin User'
        }
      }
    );

    console.log('Matched count:', result.matchedCount);
    console.log('Modified count:', result.modifiedCount);

    const user = await User.findOne({ email }).lean();
    console.log('User found:', !!user);
    console.log('Stored email:', user?.email);

    await mongoose.disconnect();
    console.log(`Password reset successfully for ${email}`);
    process.exit(0);
  } catch (error) {
    console.error('Password reset failed:', error);
    try {
      await mongoose.disconnect();
    } catch {}
    process.exit(1);
  }
}

resetPassword();
