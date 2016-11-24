
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3012
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31825);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-3012: audit");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3012 (audit)");
 script_set_attribute(attribute: "description", value: "The audit package contains the user space utilities for
storing and searching the audit records generate by
the audit subsystem in the Linux 2.6 kernel.

-
Update Information:

This release fixes the init script headers to not provide LSB info. This was
causing audit to start too late.    It also fixes a problem where saddr fields
were not being decoded correctly on avc events in ausearch.    This also fixes
a
buffer overflow in audit_log_user_command that is caught by FORTIFY_SOURCE,
resulting in an application crash. sudo is the only application known to use
this vulnerable function.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1628");
script_summary(english: "Check for the version of the audit package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"audit-1.6.8-4.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
