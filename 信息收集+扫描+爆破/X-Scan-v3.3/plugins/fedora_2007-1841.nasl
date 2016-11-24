
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1841
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27736);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1841: sylpheed");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1841 (sylpheed)");
 script_set_attribute(attribute: "description", value: "This program is an X based fast email client which has features
like:
o user-friendly and intuitive interface
o integrated NetNews client (partially implemented)
o ability of keyboard-only operation
o Mew/Wanderlust-like key bind
o multipart MIME
o unlimited multiple account handling
o message queueing
o assortment function
o XML-based address book

See /usr/share/doc/sylpheed*/README for more information.

-
Update Information:

Ulf Harnhammar (Secunia Research) has discovered a format string vulnerability
in sylpheed and claws-mail in inc_put_error() function in src/inc.c when displa
ying POP3 error reply.

Problem can be exploited by malicious POP3 server via specially crafted POP3 se
rver replies containing format specifiers.

Successful exploitation may allow execution of arbitrary code, but requires tha
t the user is tricked into connecting to a malicious POP3 server.

Secunia advisory: [8]http://secunia.com/advisories/26550/

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-2958");
script_summary(english: "Check for the version of the sylpheed package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"sylpheed-2.3.1-5", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
