const express = require('express');
const router = express.Router();

const { asyncHandler } = require('../auth/checkAuth');

const controllerUser = require('../controllers/users.controller');
router.post('/api/register', asyncHandler(controllerUser.register));
router.post('/api/login', asyncHandler(controllerUser.login));

router.post('/api/login-google', asyncHandler(controllerUser.loginGoogle));
module.exports = router;
