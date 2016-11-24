
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14045);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:062: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:062 (cups).");
 script_set_attribute(attribute: "description", value: "A Denial of Service (DoS) vulnerability was discovered in the CUPS
printing system by Phil D'Amore of Red Hat. The IPP (Internet Printing
Protocol) that CUPS uses is single-threaded and can only service one
request at a time. A malicious user could create a partial request
that does not time out and cause a Denial of Service condition where
CUPS will not respond to other printing requests. This can only be
done if the malicious user can create a TCP connection to the IPP
port (631 by default).
This vulnerability has been fixed upstream in CUPS 1.1.19 and packages
of previous versions have been fixed to correct the problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:062");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0195");
script_summary(english: "Check for the version of the cups package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.1.18-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.18-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.18-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.18-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.18-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.18-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.18-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.18-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.18-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.18-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.19-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.19-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.19-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups1-1.1.19-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups1-devel-1.1.19-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"MDK8.2")
 || rpm_exists(rpm:"cups-", release:"MDK9.0")
 || rpm_exists(rpm:"cups-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0195", value:TRUE);
}
exit(0, "Host is not affected");
