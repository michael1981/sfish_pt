
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3379
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32101);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-3379: qt4");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3379 (qt4)");
 script_set_attribute(attribute: "description", value: "Qt is a software toolkit for developing applications.

This package contains base tools, like string, xml, and network
handling.

-
References:

[ 1 ] Bug #443766 - CVE-2008-1670 kdelibs: Buffer overflow in KHTML's image l
oader
[9]https://bugzilla.redhat.com/show_bug.cgi?id=443766
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1670");
script_summary(english: "Check for the version of the qt4 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"qt4-4.3.4-11.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
