const express = require('express');
const app = express();
const { mongoose } = require('./db/mongoose');
// Load in the mongoose models
const { List, Task, User } = require('./db/models');

//#region MIDDLEWARE

// Load middleware
// bodyParser is deprecated express: https://stackoverflow.com/questions/24330014/bodyparser-is-deprecated-express-4
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS HEADERS MIDDLEWARE
app.use(function (req, res, next) {
	res.header("Access-Control-Allow-Origin", "*");
	res.header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE");
	res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, x-access-token, x-refresh-token, _id");

	res.header(
		'Access-Control-Expose-Headers',
		'x-access-token, x-refresh-token'
	);

	next();
});

// verify refresh token middleware
let verifySession = (req, res, next) => {
	// get refresh token from the request header
	let refreshToken = req.header('x-refresh-token');

	// get id from the request header
	let _id = req.header('_id');

	User.findByIdAndToken(_id, refreshToken).then((user) => {
		// user not found
		if (!user) {
			return Promise.reject({
				'error': 'User not found'
			});
		}

		// check if the refresh is valid
		req.user_id = user._id;
		req.userObject = user;
		req.refreshToken = refreshToken;
		
		let isSessionValid = false;
		
		user.sessions.forEach((session) => {
			if (session.token === refreshToken) {
				// check if the session is expired
				if (User.hasRefreshTokenExpired(session.expiresAt) === false)
					isSessionValid = true;
			}
		})

		if (isSessionValid) {
			// valid
			next();
		}
		else {
			return Promise.reject({
				'error': 'Refresh token expired or the session is not valid'
			})
		}
	}).catch((e) => {
		res.status(401).send(e);
	})
};

//#endregion


/* ROUTE HANDLERS */

/* LIST ROUTES */

/**
 * GET /lists
 * Purpose: Get all lists
 */
app.get('/lists', (req, res) => {
	// We want to return an array of all the lists that belong to the authenticated user 
	List.find().then((lists) => {
		res.send(lists);
	});
})

/**
 * POST /lists
 * Purpose: Create a list
 */
app.post('/lists', (req, res) => {
	// We want to create a new list and return the new list document back to the user (which includes the id)
	// The list information (fields) will be passed in via the JSON request body
	let title = req.body.title;

	let newList = new List({
		title
	});

	newList.save().then((listDoc) => {
		// the full list document is returned (incl. id)
		res.send(listDoc);
	})
})

/**
 * PATCH /lists/:id
 * Purpose: Update a specified list
 */
app.patch('/lists/:id', (req, res) => {
	// We want to update the specified list (list document with id in the URL) with the new values specified in the JSON body of the request
	List.findOneAndUpdate({ _id: req.params.id }, {
		$set: req.body
	}).then(() => {
		res.sendStatus(200);
	});
})

/**
 * DELETE /lists/:id
 * Purpose: Delete a list
 */
app.delete('/lists/:id', (req, res) => {
	// We want to delete the specified list (document with id in the URL)
	List.findOneAndRemove({
		_id: req.params.id
	}).then((removedListDoc) => {
		res.send(removedListDoc);
	})
})

/**
 * GET /lists/:listId/tasks
 * Purpose: Get all tasks in a specific list
 */
app.get('/lists/:listId/tasks', (req, res) => {
	// We want to return all tasks that belong to a specific list (specified by listId)
	Task.find({
		_listId: req.params.listId
	}).then((tasks) => {
		res.send(tasks);
	})
});

/**
 * POST /lists/:listId/tasks
 * Purpose: Create a new task in a specific list
 */
app.post('/lists/:listId/tasks', (req, res) => {
	// We want to create a new task in a list specified by listId
	let newTask = new Task({
		title: req.body.title,
		_listId: req.params.listId
	});
	newTask.save().then((newTaskDoc) => {
		res.send(newTaskDoc);
	})
})

/**
 * PATCH /lists/:listId/tasks/:taskId
 * Purpose: Update an existing task
 */
app.patch('/lists/:listId/tasks/:taskId', (req, res) => {
	// We want to update an existing task (specified by taskId)
	Task.findOneAndUpdate({
		_id: req.params.taskId,
		_listId: req.params.listId
	}, {
		$set: req.body
	}
	).then(() => {
		res.send({ message: 'Updated successfully.' })
	})
});

/**
 * DELETE /lists/:listId/tasks/:taskId
 * Purpose: Delete a task
 */
app.delete('/lists/:listId/tasks/:taskId', (req, res) => {
	Task.findOneAndRemove({
		_id: req.params.taskId,
		_listId: req.params.listId
	}).then((removedTaskDoc) => {
		res.send(removedTaskDoc);
	})
})


//#region User
/**
 * POST /users
 * Purpose: sign up
 */
app.post('/users', (req, res) => {
	let body = req.body;
	let newUser = new User(body);

	newUser.save().then(() => {
		return newUser.createSession();
	}).then((refreshToken) => {
		// after created session
		// generate access token
		return newUser.generateAccessAuthToken().then((accessToken) => {
			return { accessToken, refreshToken }
		});
	}).then((authTokens) => {
		res.header('x-refresh-token', authTokens.refreshToken)
			.header('x-access-token', authTokens.accessToken)
			.send(newUser);
	}).catch((err) => {
		res.status(400).send(err);
	})
})

//#region User
/**
 * POST /users/login
 * Purpose: login
 */
app.post('/users/login', (req, res) => {
	let email = req.body.email;
	let password = req.body.password;

	User.findByCredentials(email, password).then((user) => {
		return user.createSession().then((refreshToken) => {
			// after created session
			// generate access token

			return user.generateAccessAuthToken().then((accessToken) => {
				return { accessToken, refreshToken }
			});
		}).then((authTokens) => {
			res.header('x-refresh-token', authTokens.refreshToken)
				.header('x-access-token', authTokens.accessToken)
				.send(user);
		});
	}).catch((err) => {
		res.status(400).send(err);
	})
})

/**
 * GET /users/me/access-token
 * Purpose: generate and returns an access token
 */
app.get('/users/me/access-token', verifySession, (req, res) => {
	// route goes to verifySession
	// user_id
	// userObject
	req.userObject.generateAccessAuthToken().then((accessToken) => {
		res.header('x-access-token', accessToken).send({ accessToken });
	}).catch((e) => {
		res.status(400).send(e);
	})
})

//#endregion

app.listen(3000, () => {
	console.log("server is 3000")
})