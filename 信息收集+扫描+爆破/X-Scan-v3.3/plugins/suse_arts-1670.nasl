
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27154);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  arts: Security Update to add missing setuid() return checks. (arts-1670)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch arts-1670");
 script_set_attribute(attribute: "description", value: "The KDE soundserver aRts lacked checks around some setuid() 
calls.  This could potentially be used by a local attacker 
to gain root privileges. (CVE-2006-2916)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch arts-1670");
script_end_attributes();

script_cve_id("CVE-2006-2916");
script_summary(english: "Check for the arts-1670 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"arts-1.5.1-15.3", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"arts-32bit-1.5.1-15.3", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"arts-64bit-1.5.1-15.3", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
