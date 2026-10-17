const express = require("express");
const codeAuditController = require("../controllers/codeAuditController");
const { requireAuth } = require("../middleware/authMiddleware");

const router = express.Router();

router.use(requireAuth);
router.post("/", codeAuditController.submitRepository);
router.get("/", codeAuditController.listScans);
router.get("/projects", codeAuditController.listProjects);
router.delete("/projects/:scanId", codeAuditController.deleteProject);
router.get("/:scanId", codeAuditController.getScan);

module.exports = router;
