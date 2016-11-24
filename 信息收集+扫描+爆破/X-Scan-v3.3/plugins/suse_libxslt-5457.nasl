
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34076);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for libxslt (libxslt-5457)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libxslt-5457");
 script_set_attribute(attribute: "description", value: "A heap overflow in the RC4 cryptographic routines in
libxslt was fixed which could be used by attackers to
potentially execute code. (CVE-2008-2935)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libxslt-5457");
script_end_attributes();

script_cve_id("CVE-2008-2935");
script_summary(english: "Check for the libxslt-5457 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"libxslt-1.1.15-15.11", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libxslt-devel-1.1.15-15.11", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libxslt-1.1.15-15.11", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libxslt-devel-1.1.15-15.11", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libxslt-1.1.15-15.11", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libxslt-devel-1.1.15-15.11", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
