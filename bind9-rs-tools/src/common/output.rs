//! Output rendering shared across tools: the `dns_master_style` column
//! layout (name → 24, ttl → 32, class → 40, type → 48; tab width 8),
//! statistics blocks, header lines (§16 of the main spec, §42 of the
//! addendum).  `tools::dig::output` implements the first courted surface.
//!
//! Status: PARTIAL — dig's renderer; consolidation target for host/
//! nslookup/delv output as they land.
