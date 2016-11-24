
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39573);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:146: imap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:146 (imap).");
 script_set_attribute(attribute: "description", value: "Security vulnerabilities has been identified and fixed in University
of Washington IMAP Toolkit:
Multiple stack-based buffer overflows in (1) University of Washington
IMAP Toolkit 2002 through 2007c, (2) University of Washington Alpine
2.00 and earlier, and (3) Panda IMAP allow (a) local users to gain
privileges by specifying a long folder extension argument on the
command line to the tmail or dmail program; and (b) remote attackers to
execute arbitrary code by sending e-mail to a destination mailbox name
composed of a username and '+' character followed by a long string,
processed by the tmail or possibly dmail program (CVE-2008-5005).
smtp.c in the c-client library in University of Washington IMAP Toolkit
2007b allows remote SMTP servers to cause a denial of service (NULL
pointer dereference and application crash) by responding to the QUIT
command with a close of the TCP connection instead of the expected
221 response code (CVE-2008-5006).
Off-by-one error in the rfc822_output_char function in the RFC822BUFFER
routines in the University of Washington (UW) c-client library, as
used by the UW IMAP toolkit before imap-2007e and other applications,
allows context-dependent attackers to cause a denial of service (crash)
via an e-mail message that triggers a buffer overflow (CVE-2008-5514).
The updated packages have been patched to prevent this. Note that the
software was renamed to c-client starting from Mandriva Linux 2009.0
and only provides the shared c-client library for the imap functions
in PHP.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:146");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-5005", "CVE-2008-5006", "CVE-2008-5514");
script_summary(english: "Check for the version of the imap package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"imap-2006k-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imap-devel-2006k-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imap-utils-2006k-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libc-client-php0-2006k-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libc-client-php-devel-2006k-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libc-client0-2007b-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libc-client-devel-2007b-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"imap-", release:"MDK2008.1")
 || rpm_exists(rpm:"imap-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-5005", value:TRUE);
 set_kb_item(name:"CVE-2008-5006", value:TRUE);
 set_kb_item(name:"CVE-2008-5514", value:TRUE);
}
exit(0, "Host is not affected");
