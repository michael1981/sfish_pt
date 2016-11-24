
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3453
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36126);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-3453: device-mapper-multipath");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3453 (device-mapper-multipath)");
 script_set_attribute(attribute: "description", value: "device-mapper-multipath provides tools to manage multipath devices by instructi
ng the
device-mapper multipath kernel module what to do.
The tools are :
* multipath :   Scan the system for multipath devices and assemble them.
* multipathd :  Detects when paths fail and execs multipath to update things.

-
Update Information:

Fix insecure permissions on multipathd.sock (CVE-2009-0115)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0115");
script_summary(english: "Check for the version of the device-mapper-multipath package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"device-mapper-multipath-0.4.7-17.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
