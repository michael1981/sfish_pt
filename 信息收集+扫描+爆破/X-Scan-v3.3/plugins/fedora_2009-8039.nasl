
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8039
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40412);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-8039: kdelibs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8039 (kdelibs)");
 script_set_attribute(attribute: "description", value: "Libraries for the K Desktop Environment 4.

-
Update Information:

This update fixes several security issues in KHTML (CVE-2009-1725,
CVE-2009-1690, CVE-2009-1687, CVE-2009-1698, CVE-2009-0945, CVE-2009-2537) whic
h
may lead to a denial of service or potentially even arbitrary code execution.
In addition, libplasma was fixed to make Plasmaboard (a virtual keyboard applet
)
work, and a bug in a Fedora patch which made builds of the SRPM on single-CPU
machines fail was fixed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0945", "CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698", "CVE-2009-1725", "CVE-2009-2537");
script_summary(english: "Check for the version of the kdelibs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kdelibs-4.2.4-6.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
