
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-207
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24303);
 script_version ("$Revision: 1.7 $");
script_name(english: "Fedora 5 2007-207: wireshark");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-207 (wireshark)");
 script_set_attribute(attribute: "description", value: "Wireshark is a network traffic analyzer for Unix-ish operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, contains plugins and
documentation for wireshark. A graphical user interface is packaged
separately to GTK+ package.

Update Information:

- multiple security issues fixed (#227140)
- CVE-2007-0459 - The TCP dissector could hang or crash
while reassembling HTTP packets
- CVE-2007-0459 - The HTTP dissector could crash.
- CVE-2007-0457 - On some systems, the IEEE 802.11 dissector
could crash.
- CVE-2007-0456 - On some systems, the LLT dissector could
crash.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-4332", "CVE-2006-4574", "CVE-2006-4805", "CVE-2006-5468", "CVE-2006-5469", "CVE-2006-5740", "CVE-2007-0456", "CVE-2007-0457", "CVE-2007-0459");
script_summary(english: "Check for the version of the wireshark package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"wireshark-0.99.5-1.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
