
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8329
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40507);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-8329: java-1.6.0-openjdk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8329 (java-1.6.0-openjdk)");
 script_set_attribute(attribute: "description", value: "The OpenJDK runtime environment.

-
Update Information:

Urgent security updates have been included
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0217", "CVE-2009-1896", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2689", "CVE-2009-2690");
script_summary(english: "Check for the version of the java-1.6.0-openjdk package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"java-1.6.0-openjdk-1.6.0.0-27.b16.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
