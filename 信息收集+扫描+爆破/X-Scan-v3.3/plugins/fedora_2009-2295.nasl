
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2295
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35769);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-2295: psi");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2295 (psi)");
 script_set_attribute(attribute: "description", value: "Psi is the premiere Instant Messaging application designed for Microsoft
Windows, Apple Mac OS X and GNU/Linux. Built upon an open protocol named
Jabber, Psi is a fast and lightweight messaging client that utilises the best
in open source technologies. Psi contains all the features necessary to chat,
with no bloated extras that slow your computer down. The Jabber protocol
provides gateways to other protocols as AIM, ICQ, MSN and Yahoo!.
If you want SSL support, install the qca-tls package.

-
Update Information:

This is a security-bugfix-only update to version 0.12.1 fixing a DOS
vulnerability.    New in 0.12.1   - Bugfix for DOS vulnerability in the file
transfer code.     Thanks to Jesus Olmos (jolmos isecauditors com)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-6393");
script_summary(english: "Check for the version of the psi package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"psi-0.12.1-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
