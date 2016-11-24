
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1323
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(30238);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-1323: perl-Tk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1323 (perl-Tk)");
 script_set_attribute(attribute: "description", value: "This a re-port of a perl interface to Tk8.4.
C code is derived from Tcl/Tk8.4.5.
It also includes all the C code parts of Tix8.1.4 from SourceForge.
The perl code corresponding to Tix's Tcl code is not fully implemented.

Perl API is essentially the same as Tk800 series Tk800.025 but has not
been verified as compliant. There ARE differences see pod/804delta.pod.

-
ChangeLog:


Update information :

* Tue Feb  5 2008 Andreas Bierfert <andreas.bierfert[AT]lowlatency.de>
- 804.028-3
- fix #431529 gif overflow in tk (see also #431518)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0553");
script_summary(english: "Check for the version of the perl-Tk package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"perl-Tk-804.028-3.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
