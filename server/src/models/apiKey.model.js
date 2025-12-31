const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const modelApiKey = new Schema(
    {
        userId: { type: Schema.Types.ObjectId, ref: 'users', require: true },
        publicKey: { type: String, require: true },
        privateKey: { type: String, require: true },
    },
    {
        timestamps: true,
    },
);

module.exports = mongoose.model('apikey', modelApiKey);
