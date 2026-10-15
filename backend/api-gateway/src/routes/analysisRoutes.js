const express = require("express");
const analysisController = require("../controllers/analysisController");
const { requireAuth } = require("../middleware/authMiddleware");

const router = express.Router();

router.use(requireAuth);
router.post("/", analysisController.analyze);
router.get("/history", analysisController.history);
router.get("/:analysisId", analysisController.getAnalysis);

module.exports = router;
