
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37634);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:074: libneon0.27");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:074 (libneon0.27).");
 script_set_attribute(attribute: "description", value: "A security vulnerability has been identified and fixed in neon:
neon 0.28.0 through 0.28.2 allows remote servers to cause a denial
of service (NULL pointer dereference and crash) via vectors related
to Digest authentication and Digest domain parameter support
(CVE-2008-3746).
The updated packages have been upgraded to version 0.28.3 to prevent
this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:074");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3746");
script_summary(english: "Check for the version of the libneon0.27 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libneon0.27-0.28.3-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libneon0.27-devel-0.28.3-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libneon0.27-static-devel-0.28.3-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libneon0.27-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-3746", value:TRUE);
}
exit(0, "Host is not affected");
