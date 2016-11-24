
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1036
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(30086);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-1036: icu");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1036 (icu)");
 script_set_attribute(attribute: "description", value: "Tools and utilities for developing with icu.

-
Update Information:

CVE-2007-4770 & CVE-2007-4771    Flaws in icu regexp handling.     Technical
details can be found at [9]http://sourceforge.net/mailarchive/message.php?msg_n
ame=
d03a2ffb0801221538x68825e42xb4a4aaf0fcccecbd%2540mail.gmail.com
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-4771");
script_summary(english: "Check for the version of the icu package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"icu-3.8-5.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
