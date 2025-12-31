const express = require('express');
const router = express.Router();

const { asyncHandler } = require('../auth/checkAuth');

const controllerUser = require('../controllers/users.controller');

router.post('/api/register', asyncHandler(controllerUser.register));

module.exports = router;
