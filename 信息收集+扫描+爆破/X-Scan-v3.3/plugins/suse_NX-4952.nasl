
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30121);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  NX security update (NX-4952)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch NX-4952");
 script_set_attribute(attribute: "description", value: "This update fixes various Xserver security issues that are
also present in NX:

XInput Extension Memory Corruption Vulnerability [IDEF2888
CVE-2007-6427].

TOG-CUP Extension Memory Corruption Vulnerability [IDEF2901
CVE-2007-6428].

EVI Extension Integer Overflow Vulnerability [IDEF2902
CVE-2007-6429].

MIT-SHM Extension Integer Overflow Vulnerability [IDEF2904
CVE-2007-6429].
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch NX-4952");
script_end_attributes();

script_cve_id("CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2007-6429");
script_summary(english: "Check for the NX-4952 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"NX-2.1.0-35.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
