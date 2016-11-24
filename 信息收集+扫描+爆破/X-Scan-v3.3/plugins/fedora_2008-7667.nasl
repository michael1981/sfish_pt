
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7667
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34279);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-7667: initscripts");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7667 (initscripts)");
 script_set_attribute(attribute: "description", value: "The initscripts package contains the basic system scripts used to boot
your Red Hat or Fedora system, change runlevels, and shut the system down
cleanly.  Initscripts also contains the scripts that activate and
deactivate most network interfaces.

-
Update Information:

This update fixes an issue (CVE-2008-3524) where a malicious user could cause
system files to be removed on startup. It also fixes a bug when running on pre-
Fedora-9 kernels, and cleans up some extraneous error messages.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3524");
script_summary(english: "Check for the version of the initscripts package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"initscripts-8.76.3-1", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
