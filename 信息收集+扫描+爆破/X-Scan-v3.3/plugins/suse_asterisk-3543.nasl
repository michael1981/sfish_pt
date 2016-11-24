
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27157);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  asterisk security update (asterisk-3543)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch asterisk-3543");
 script_set_attribute(attribute: "description", value: "This update fixes multiple bugs that allowed attackers to
remotely crash asterisk or cause an information leak
(CVE-2007-1561, CVE-2007-1594, CVE-2007-1595,
CVE-2007-2297, CVE-2007-2488).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch asterisk-3543");
script_end_attributes();

script_cve_id("CVE-2007-1561", "CVE-2007-1594", "CVE-2007-1595", "CVE-2007-2297", "CVE-2007-2488");
script_summary(english: "Check for the asterisk-3543 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"asterisk-1.2.13-23", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
