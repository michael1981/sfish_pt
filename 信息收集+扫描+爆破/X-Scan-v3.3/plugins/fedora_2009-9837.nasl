
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9837
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42387);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-9837: wireshark");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9837 (wireshark)");
 script_set_attribute(attribute: "description", value: "Wireshark is a network traffic analyzer for Unix-ish operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, contains plugins and
documentation for wireshark. A graphical user interface is packaged
separately to GTK+ package.

-
Update Information:

Update to Wireshark 1.2.2 fixing multiple security issues:
[9]http://www.wireshark.org/docs/relnotes/wireshark-1.2.2.html
[10]http://www.wireshark.org/security/wnpa-sec-2009-06.html        * The OpcUa
dissector could use excessive CPU and memory. (Bug 3986)        Versions
affected: 0.99.6 to 1.0.8, 1.2.0 to 1.2.1      * The GSM A RR dissector could
crash. (Bug 3893)        Versions affected: 1.2.0 to 1.2.1      * The TLS
dissector could crash on some platforms. (Bug 4008)        Versions affected:
1.2.0 to 1.2.1     [11]http://www.wireshark.org/docs/relnotes/wireshark-1.2.1.h
tml
[12]http://www.wireshark.org/security/wnpa-sec-2009-04.html        * The AFS
dissector could crash. (Bug 3564)        Versions affected: 0.9.2 to 1.2.0

Update information :

* The Infiniband dissector could crash on some platforms.        Versions
affected: 1.0.6 to 1.2.0      *  The IPMI dissector could overrun a buffer.
(Bug 3559)        Versions affected: 1.2.0      * The Bluetooth L2CAP dissector
could crash. (Bug 3572)        Versions affected: 1.2.0      * The RADIUS
dissector could crash. (Bug 3578)        Versions affected: 1.2.0      * The
MIOP dissector could crash. (Bug 3652)        Versions affected: 1.2.0      *
The sFlow dissector could use excessive CPU and memory. (Bug 3570)
Versions affected: 1.2.0    (Issues from wnpa-sec-2009-04 does not affect users
of Wireshark 1.2.1 packages from updates-testing.)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2559", "CVE-2009-2560", "CVE-2009-2561", "CVE-2009-2562", "CVE-2009-2563", "CVE-2009-3241", "CVE-2009-3242");
script_summary(english: "Check for the version of the wireshark package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"wireshark-1.2.2-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
