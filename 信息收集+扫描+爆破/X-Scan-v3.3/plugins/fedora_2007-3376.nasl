
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-3376
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28216);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-3376: php-pear-MDB2-Driver-mysqli");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-3376 (php-pear-MDB2-Driver-mysqli)");
 script_set_attribute(attribute: "description", value: "This is the MySQL Improved MDB2 driver.

-
Update Information:

This update fixes a security flaw CVE-2007-5934 with critical impact. All users
of php-pear-MDB2 are strongly advised to upgrade to these updated packages.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5934");
script_summary(english: "Check for the version of the php-pear-MDB2-Driver-mysqli package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"php-pear-MDB2-Driver-mysqli-1.4.1-3.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
