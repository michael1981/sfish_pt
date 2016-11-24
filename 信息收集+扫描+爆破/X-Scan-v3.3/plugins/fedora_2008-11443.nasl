
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11443
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36460);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2008-11443: libvirt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11443 (libvirt)");
 script_set_attribute(attribute: "description", value: "Libvirt is a C toolkit to interact with the virtualization capabilities
of recent versions of Linux (and other OSes).

-
Update Information:

fix missing read-only access checks, fixes CVE-2008-5086  - upstream release
0.5.1  - mostly bugfixes e.g #473071  - some driver improvements
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5086");
script_summary(english: "Check for the version of the libvirt package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libvirt-0.5.1-2.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
