
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34359);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for CUPS (cups-5653)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch cups-5653");
 script_set_attribute(attribute: "description", value: "Specially crafted print jobs could trigger buffer overflows
in the 'imagetops', 'texttops' and 'hpgltops' filters.
Attackers could potentially exploit that to execute
arbitrary code on the cups server (CVE-2008-3639,
CVE-2008-3640, CVE-2008-3641).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch cups-5653");
script_end_attributes();

script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641");
script_summary(english: "Check for the cups-5653 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"cups-1.1.23-40.46", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.23-40.46", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.23-40.46", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.23-40.46", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-1.1.23-40.46", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.23-40.46", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.23-40.46", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.23-40.46", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-1.1.23-40.46", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.23-40.46", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.23-40.46", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.23-40.46", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
