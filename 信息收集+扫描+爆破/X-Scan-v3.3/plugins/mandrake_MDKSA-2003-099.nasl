
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14081);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:099: sane");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:099 (sane).");
 script_set_attribute(attribute: "description", value: "Several vulnerabilities were discovered in the saned daemon, a part of
the sane package, which allows for a scanner to be used remotely. The
IP address of the remote host is only checked after the first
communication occurs, which causes the saned.conf restrictions to be
ignored for the first connection. As well, a connection that is
dropped early can cause Denial of Service issues due to a number of
differing factors. Finally, a lack of error checking can cause various
other unfavourable actions.
The provided packages have been patched to correct the issues. sane,
as distributed in Mandrake Linux 9.1 and higher, have versions where
the fixes were applied upstream.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:099");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0773", "CVE-2003-0774", "CVE-2003-0775", "CVE-2003-0776", "CVE-2003-0777", "CVE-2003-0778");
script_summary(english: "Check for the version of the sane package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libsane1-1.0.9-3.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsane1-devel-1.0.9-3.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sane-backends-1.0.9-3.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"sane-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0773", value:TRUE);
 set_kb_item(name:"CVE-2003-0774", value:TRUE);
 set_kb_item(name:"CVE-2003-0775", value:TRUE);
 set_kb_item(name:"CVE-2003-0776", value:TRUE);
 set_kb_item(name:"CVE-2003-0777", value:TRUE);
 set_kb_item(name:"CVE-2003-0778", value:TRUE);
}
exit(0, "Host is not affected");
