const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/auth');
const autofillController = require('../controllers/autofillController');

router.get('/', authMiddleware, autofillController.getAutofillData);

module.exports = router;
