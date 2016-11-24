
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31842);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  openssh security update (openssh-5148)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch openssh-5148");
 script_set_attribute(attribute: "description", value: "A flaw in the X forwarding code of openssh allowed
malicious users to steal the X access credentials of other
users (CVE-2008-1483).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch openssh-5148");
script_end_attributes();

script_cve_id("CVE-2008-1483");
script_summary(english: "Check for the openssh-5148 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"openssh-4.2p1-18.36", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.2p1-18.36", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
