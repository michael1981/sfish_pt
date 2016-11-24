
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-511
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24099);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 4 2006-511: busybox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-511 (busybox)");
 script_set_attribute(attribute: "description", value: "Busybox is a single binary which includes versions of a large number
of system commands, including a shell.  This package can be very
useful for recovering from certain types of system failures,
particularly those involving broken shared libraries.

Update Information:

The BusyBox passwd command does not use a proper salt when
generating passwords. This would create an instance where a
brute force attack could take very little time.
This problem is fixed in busybox-1.00-5.fc4.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-1058");
script_summary(english: "Check for the version of the busybox package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"busybox-1.00-5.fc4", release:"FC4") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
