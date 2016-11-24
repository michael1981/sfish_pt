
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29431);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for flac (flac-4569)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch flac-4569");
 script_set_attribute(attribute: "description", value: "Multiple integer overflows in flac could potentially be
exploited by attackers via specially crafted files to
execute code in the context of the user opening the file
(CVE-2007-4619).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch flac-4569");
script_end_attributes();

script_cve_id("CVE-2007-4619");
script_summary(english: "Check for the flac-4569 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"flac-1.1.2-15.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"flac-devel-1.1.2-15.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"flac-1.1.2-15.7", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"flac-devel-1.1.2-15.7", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
