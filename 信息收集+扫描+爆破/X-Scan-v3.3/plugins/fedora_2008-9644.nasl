
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9644
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34774);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-9644: clamav");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9644 (clamav)");
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

Security fixes from upstream 0.94 and 0.94.1:    CVE-2008-1389 (#461461):
Invalid memory access in the CHM unpacker  CVE-2008-3912 (#461461): Multiple
out-of-memory NULL pointer dereferences  CVE-2008-3913 (#461461): Fix memory
leak in the error code path in freshclam  CVE-2008-3914 (#461461): Multiple fil
e
descriptor leaks on the error code path  CVE-2008-5050 (#470783):
get_unicode_name() off-by-one buffer overflow
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1389", "CVE-2008-2713", "CVE-2008-3215", "CVE-2008-3912", "CVE-2008-3913", "CVE-2008-3914", "CVE-2008-5050");
script_summary(english: "Check for the version of the clamav package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"clamav-0.93.3-2.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
