const express = require("express");
const adminController = require("../controllers/adminController");
const analysisController = require("../controllers/analysisController");
const codeAuditController = require("../controllers/codeAuditController");
const { requireAuth } = require("../middleware/authMiddleware");
const { requireRole } = require("../middleware/roleMiddleware");
const { listAllRecords } = require("../utils/ownership");

const router = express.Router();

router.use(requireAuth, requireRole("ADMIN"));

router.get("/users", adminController.getUsers);
router.get("/users/:id", adminController.getUserById);
router.patch("/users/:id/status", adminController.updateUserStatus);
router.patch("/users/:id/role", adminController.updateUserRole);

router.get("/analyses", listAllRecords, analysisController.history);
router.get("/code-audits", listAllRecords, codeAuditController.listScans);

module.exports = router;
