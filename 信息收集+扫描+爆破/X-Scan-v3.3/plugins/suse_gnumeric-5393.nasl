
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33559);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  gnumeric security update (gnumeric-5393)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gnumeric-5393");
 script_set_attribute(attribute: "description", value: "Specially crafed xls files could trigger integer overflows
in gnumeric that could potentially be exploited to execute
arbitrary code (CVE-2008-0668).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch gnumeric-5393");
script_end_attributes();

script_cve_id("CVE-2008-0668");
script_summary(english: "Check for the gnumeric-5393 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gnumeric-1.7.11-32.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gnumeric-devel-1.7.11-32.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
