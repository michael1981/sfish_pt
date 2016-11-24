
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3488
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32200);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-3488: bugzilla");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3488 (bugzilla)");
 script_set_attribute(attribute: "description", value: "Bugzilla is a popular bug tracking system used by multiple open source
projects.  It requires a database engine installed - either MySQL or
PostgreSQL.  Without one of these database engines, Bugzilla will not work.

-
Update Information:

Update to upstream 3.0.4 to resolve multiple security vulns
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2103", "CVE-2008-2105");
script_summary(english: "Check for the version of the bugzilla package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"bugzilla-3.0.4-1.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
