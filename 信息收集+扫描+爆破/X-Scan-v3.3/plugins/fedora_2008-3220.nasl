
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3220
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32037);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-3220: fedora-ds-admin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3220 (fedora-ds-admin)");
 script_set_attribute(attribute: "description", value: "Fedora Administration Server is an HTTP agent that provides management features
for Fedora Directory Server.  It provides some management web apps that can
be used through a web browser.  It provides the authentication, access control,
and CGI utilities used by the console.

-
Update Information:

This release addresses two security vulerabilities in the package:  - shell
command injection in CGI replication monitor (CVE-2008-0892)  - unrestricted
access to CGI scripts (CVE-2008-0893)    Fix Description:  Remove ScriptAlias
for bin/admin/admin/bin - do not use that directory for CGI URIs - use only
protected URIs for CGIs requiring authentication  Remove most CGI parameters
from repl-monitor-cgi.pl - user must supply replmon.conf in the admin server
config directory instead of passing in this pathname - repl-monitor-cgi.pl does
not use system to call repl-monitor.pl, it 'includes' that script (using perl
import).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0892", "CVE-2008-0893");
script_summary(english: "Check for the version of the fedora-ds-admin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"fedora-ds-admin-1.1.4-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
