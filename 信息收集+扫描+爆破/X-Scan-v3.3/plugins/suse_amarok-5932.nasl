
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35552);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  amarok: fixed remote code execution bug (amarok-5932)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch amarok-5932");
 script_set_attribute(attribute: "description", value: "This update of amarok fixes several integer overflows and
unchecked memory allocations that can be exploited by
malformed Audible digital audio files. These bugs could be
used in a user-assisted attack scenario to execute
arbitrary code remotely. (CVE-2009-0135, CVE-2009-0136)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch amarok-5932");
script_end_attributes();

script_cve_id("CVE-2009-0135", "CVE-2009-0136");
script_summary(english: "Check for the amarok-5932 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"amarok-1.4.7-37.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"amarok-lang-1.4.7-37.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"amarok-libvisual-1.4.7-37.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"amarok-xine-1.4.7-37.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"amarok-yauap-1.4.7-37.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
