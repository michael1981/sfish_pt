
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8340
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40830);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-8340: firebird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8340 (firebird)");
 script_set_attribute(attribute: "description", value: "This package contains common files between firebird-classic and
firebird-superserver. You will need this if you want to use either one.

-
Update Information:

Upgrade from previous package version may be a problem  since previous version
remove /var/run/firebird and it shouldn't    This release fix this problem for
future updates  If you are in that case (no longer /var/run/firebird directory
after upgrade), just reinstall firebird-2.1.3.18185.0-2 package    or create
/var/run/firebird owned by user firebird
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2620");
script_summary(english: "Check for the version of the firebird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"firebird-2.1.3.18185.0-2.fc11", release:"FC11") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
