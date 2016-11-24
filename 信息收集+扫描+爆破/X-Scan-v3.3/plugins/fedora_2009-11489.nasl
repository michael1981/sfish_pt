
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-11489
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42805);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 12 2009-11489: java-1.6.0-openjdk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-11489 (java-1.6.0-openjdk)");
 script_set_attribute(attribute: "description", value: "The OpenJDK runtime environment.

-
Update Information:

Add latest security patches  Bug numbers:510197, 530053, 530057, 530061, 530062
,
530063, 530067, 530098, 530173, 530175, 530296, 530297, 530300
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3883", "CVE-2009-3884");
script_summary(english: "Check for the version of the java-1.6.0-openjdk package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"java-1.6.0-openjdk-1.6.0.0-33.b16.fc12", release:"FC12") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
