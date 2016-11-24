
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-0170
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(30071);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-0170: clamav");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-0170 (clamav)");
 script_set_attribute(attribute: "description", value: "Clam AntiVirus is an anti-virus toolkit for UNIX. The main purpose of this
software is the integration with mail servers (attachment scanning). The
package provides a flexible and scalable multi-threaded daemon, a command
line scanner, and a tool for automatic updating via Internet. The programs
are based on a shared library distributed with the Clam AntiVirus package,
which you can use with your own software. The virus database is based on
the virus database from OpenAntiVirus, but contains additional signatures
(including signatures for popular polymorphic viruses, too) and is KEPT UP
TO DATE.

-
Update Information:

Upstream clamav 0.92 fixes multiple security issues:
- CVE-2007-6335 (#426210)
- CVE-2007-6336 (#426343)
- CVE-2007-6337 (#426344)

Sendmail-specific parts moved to separate milter subpackage.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-4510", "CVE-2007-6335", "CVE-2007-6336", "CVE-2007-6337");
script_summary(english: "Check for the version of the clamav package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"clamav-0.92-6.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
