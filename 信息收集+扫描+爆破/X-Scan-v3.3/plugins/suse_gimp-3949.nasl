
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27236);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  gimp: Security fix for a integer overflow in PSD handling (gimp-3949)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gimp-3949");
 script_set_attribute(attribute: "description", value: "The image editor GIMP was updated to fix a integer overflow
in the handling of PSD files. By providing a crafted PSD
file and tricking the user to open it an attacker could
execute code. (CVE-2007-2949)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gimp-3949");
script_end_attributes();

script_cve_id("CVE-2007-2949");
script_summary(english: "Check for the gimp-3949 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gimp-2.2.13-34", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gimp-devel-2.2.13-34", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gimp-unstable-2.3.11-51.4", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gimp-unstable-devel-2.3.11-51.4", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
