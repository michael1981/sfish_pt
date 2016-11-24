
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42000);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  pidgin: remote arbitrary code execution vulnerability fixed (finch-6465)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch finch-6465");
 script_set_attribute(attribute: "description", value: "This update of pidgin fixes a remote arbitrary code
execution vulnerability in MSN SLP packet processing code.
(CORE-2009-0727)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch finch-6465");
script_end_attributes();

script_summary(english: "Check for the finch-6465 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"finch-2.3.1-26.11", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"finch-devel-2.3.1-26.11", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpurple-2.3.1-26.11", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpurple-devel-2.3.1-26.11", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpurple-meanwhile-2.3.1-26.11", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libpurple-mono-2.3.1-26.11", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pidgin-2.3.1-26.11", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pidgin-devel-2.3.1-26.11", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
