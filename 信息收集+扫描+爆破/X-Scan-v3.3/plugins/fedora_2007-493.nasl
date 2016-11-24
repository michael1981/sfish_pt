
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-493
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25183);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2007-493: dovecot");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-493 (dovecot)");
 script_set_attribute(attribute: "description", value: "Dovecot is an IMAP server for Linux/UNIX-like systems, written with security
primarily in mind.  It also contains a small POP3 server.  It supports mail
in either of maildir or mbox formats.



Update information :

* Fri Mar  2 2007 Tomas Janousek <tjanouse redhat com> - 1.0-0.beta8.4.fc5
- a little master login fix (#224925)
- fix for CVE-2007-2231 (#238440)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-5973", "CVE-2007-2231");
script_summary(english: "Check for the version of the dovecot package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"dovecot-1.0-0.beta8.4.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
