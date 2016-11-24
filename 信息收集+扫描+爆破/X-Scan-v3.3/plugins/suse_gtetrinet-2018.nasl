
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27252);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  gtetrinet: Fixed buffer overflow potential by to malicious remote servers (gtetrinet-2018)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gtetrinet-2018");
 script_set_attribute(attribute: "description", value: "Malicious tetrinet servers could overflow a buffer within
the gtetrinet client, making it possible to execute code.
CVE-2006-3125
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gtetrinet-2018");
script_end_attributes();

script_cve_id("CVE-2006-3125");
script_summary(english: "Check for the gtetrinet-2018 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gtetrinet-0.7.9-16.2", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
