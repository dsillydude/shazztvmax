// migrate.js
const mongoose = require('mongoose');
require('dotenv').config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mackdsilly1:Ourfam2019@shazztvmax.qfisgkc.mongodb.net/?retryWrites=true&w=majority&appName=ShazzTvMax';

async function runMigration() {
  console.log('▶️  Starting migration process...');
  
  try {
    // 1. Connect to the database
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB for migration.');

    const db = mongoose.connection.db;
    const collections = await db.listCollections({ name: 'users' }).toArray();
    
    if (collections.length === 0) {
      console.log('🟡  Users collection does not exist. No migration needed.');
      return; // Exit if the collection isn't there
    }

    // 2. Try to drop the old index
    try {
      console.log('⏳ Attempting to drop the unique index on "deviceId"...');
      await db.collection('users').dropIndex('deviceId_1');
      console.log('✅ Successfully dropped the old unique index: "deviceId_1"');
    } catch (error) {
      // If the index doesn't exist, MongoDB throws an error. We can safely ignore it.
      if (error.codeName === 'IndexNotFound') {
        console.log('🟡  Index "deviceId_1" was not found. It was likely already removed. Skipping.');
      } else {
        // For any other error, we should log it.
        throw error;
      }
    }
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1); // Exit with an error code
  } finally {
    // 3. Disconnect from the database
    await mongoose.disconnect();
    console.log('✅ Disconnected from MongoDB.');
    console.log('🏁 Migration process finished.');
  }
}

// Run the migration
runMigration();