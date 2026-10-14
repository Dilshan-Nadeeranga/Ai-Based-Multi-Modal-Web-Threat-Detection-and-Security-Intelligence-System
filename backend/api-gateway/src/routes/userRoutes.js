const express = require("express");
const userController = require("../controllers/userController");
const { requireAuth } = require("../middleware/authMiddleware");

const router = express.Router();

router.use(requireAuth);
router.get("/profile", userController.getProfile);
router.patch("/profile", userController.updateProfile);
router.patch("/password", userController.changePassword);

module.exports = router;
