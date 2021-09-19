const mongoose = require('mongoose');
const _ = require('lodash');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const jwtSecret = "46817775240146578339aejfsudvchgefru9275790548";

const UserSchema = new mongoose.Schema({
	email: {
		type: String,
		required: true,
		minlength: 1,
		trim: true,
		unique: true
	},
	password: {
		type: String,
		required: true,
		minlength: 8
	},
	sessions: [{
		token: {
			type: String,
			required: true
		},
		expiresAt: {
			type: Number,
			required: true
		}
	}]
})

//#region INSTANCE METHODS
UserSchema.methods.toJSON = function () {
	const user = this;
	const userObject = user.toObject();

	return _.omit(userObject, ['password', 'sessions']);
}

// create access token
UserSchema.methods.generateAccessAuthToken = function () {
	const user = this;

	return new Promise((resolve, reject) => {
		// create and return jwt
		jwt.sign({ _id: user._id.toHexString() }, jwtSecret, { expiresIn: "15m" }, (err, token) => {
			if (!err) {
				resolve(token);
			}
			else {
				reject();
			}
		})
	})
}

// create refresh token
UserSchema.methods.generateRefreshAuthToken = function () {
	return new Promise((resolve, reject) => {
		crypto.randomBytes(64, (err, buf) => {
			if (!err) {
				let token = buf.toString('hex');
				return resolve(token);
			}
		})
	})
}

UserSchema.methods.createSession = function () {
	let user = this;

	return user.generateRefreshAuthToken().then((refreshToken) => {
		return saveSessionToDatabase(user, refreshToken);
	}).then((refreshToken) => {
		return refreshToken;
	}).catch((e) => {
		return Promise.reject('Failed to save session to database.\n' + e);
	})
}
//#endregion

//#region STATIC METHODS

UserSchema.statics.getJWTSecret = () => {
	return jwtSecret;
}

// find user by id and token
UserSchema.statics.findByIdAndToken = function (_id, token) {
	const User = this;
	
	return User.findOne({
		_id,
		'sessions.token': token
	});
}

UserSchema.statics.findByCredentials = function (email, password) {
	let User = this;

	return User.findOne({ email }).then((user) => {
		if (!user) return Promise.reject;

		return new Promise((resolve, reject) => {
			bcrypt.compare(password, user.password, (err, res) => {
				if (res) resolve(user);
				else {
					reject();
				}
			})
		})
	})
}

UserSchema.statics.hasRefreshTokenExpired = (expiresAt) => {
	let timeNow = Date.now() / 1000;
	
	if (expiresAt > timeNow)
		return false;
	else
		return true;
}

//#endregion

//#region  MIDDLEWARE
// run before save the user document
UserSchema.pre('save', function (next) {
	let user = this;
	let costFactor = 10;

	if (user.isModified('password')) {
		// if the password has been changed, run this code

		// generate salt and hash password
		bcrypt.genSalt(costFactor, (err, salt) => {
			bcrypt.hash(user.password, salt, (err, hash) => {
				user.password = hash;
				next();
			})
		})
	} else {
		next();
	}
})

//#endregion


//#region HELPER METHODS
let saveSessionToDatabase = (user, refreshToken) => {
	return new Promise((resolve, reject) => {
		let expiresAt = generateRefreshTokenExpiryTime();

		// add to session array
		user.sessions.push({ 'token': refreshToken, expiresAt });

		user.save().then(() => {
			return resolve(refreshToken);
		}).catch((e) => {
			reject(e);
		})
	})
}

let generateRefreshTokenExpiryTime = () => {
	let daysUntilExpire = "10";
	let secondsUntilExpire = ((daysUntilExpire * 24) * 60) * 60;
	
	return ((Date.now() / 1000) + secondsUntilExpire);
}
//#endregion

const User = mongoose.model('User', UserSchema);
module.exports = { User }