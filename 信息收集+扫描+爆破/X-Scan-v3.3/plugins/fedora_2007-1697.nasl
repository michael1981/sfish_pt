
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1697
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27727);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1697: sysstat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1697 (sysstat)");
 script_set_attribute(attribute: "description", value: "This package provides the sar and iostat commands for Linux. Sar and
iostat enable system monitoring of disk, network, and other IO
activity.

-
ChangeLog:


Update information :

* Mon Aug 20 2007 Ivana Varekova <varekova redhat com> - 7.0.4-3
- fix cve-2007-3852 -
sysstat insecure temporary file usage
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3852");
script_summary(english: "Check for the version of the sysstat package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"sysstat-7.0.4-3.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
