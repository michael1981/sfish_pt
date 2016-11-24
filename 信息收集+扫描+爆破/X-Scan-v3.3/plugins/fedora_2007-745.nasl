
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-745
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28233);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 6 2007-745: mono");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-745 (mono)");
 script_set_attribute(attribute: "description", value: "The Mono runtime implements a JIT engine for the ECMA CLI
virtual machine (as well as a byte code interpreter, the
class loader, the garbage collector, threading system and
metadata access libraries.

Update Information:

A buffer overflow in the Mono.Math.BigInteger class in Mono
allows attackers to execute arbitrary code.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5197");
script_summary(english: "Check for the version of the mono package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mono-web-1.1.17.1-5.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
