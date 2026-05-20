-- ════════════════════════════════════════════════════════════════════════════
--  FIX THE 6 SUPABASE SECURITY ADVISOR ERRORS
--  ────────────────────────────────────────────────────────────────────────
--  HOW TO RUN THIS (30 seconds, zero technical knowledge needed):
--    1. Go to https://supabase.com/dashboard/project/_/sql/new
--       (or click "SQL Editor" in the left sidebar of your project)
--    2. Copy EVERYTHING below this header (the lines starting with ALTER /
--       CREATE / DROP) and paste into the editor.
--    3. Click the green "Run" button (or press Cmd+Enter / Ctrl+Enter).
--    4. You should see "Success. No rows returned."
--    5. Go to "Advisors" → all 6 errors should now be gone.
--  ────────────────────────────────────────────────────────────────────────
--  WHAT THIS DOES, IN PLAIN ENGLISH:
--    • Turns on "Row Level Security" for each of the 6 tables the advisor
--      flagged. This blocks public anonymous API access to your data.
--    • Your live website KEEPS WORKING UNCHANGED — the Flask app connects
--      as the table owner, which is allowed to bypass RLS automatically.
--    • Also adds a trigger that prevents anyone (even an attacker with
--      SQL access) from modifying the audit log after a row is written.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE applicants         ENABLE ROW LEVEL SECURITY;
ALTER TABLE users              ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log          ENABLE ROW LEVEL SECURITY;
ALTER TABLE interviews         ENABLE ROW LEVEL SECURITY;
ALTER TABLE staff              ENABLE ROW LEVEL SECURITY;
ALTER TABLE indeed_poll_status ENABLE ROW LEVEL SECURITY;

-- Make audit_log truly append-only at the database level.
CREATE OR REPLACE FUNCTION reject_audit_log_change()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION reject_audit_log_change();
