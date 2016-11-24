
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41481);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for Mono (bytefx-data-mysql-6353)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch bytefx-data-mysql-6353");
 script_set_attribute(attribute: "description", value: "The XML signature checker did not impose limits on the
minimum length of HMAC signatures in XML documents.
Attackers could therefore specify a length of e.g. 1 to
make the signature appear valid and therefore effectively
bypass verification of XML documents.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch bytefx-data-mysql-6353");
script_end_attributes();

script_summary(english: "Check for the bytefx-data-mysql-6353 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"mono-core-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mono-data-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mono-data-firebird-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mono-data-oracle-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mono-data-postgresql-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mono-data-sqlite-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mono-data-sybase-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mono-locale-extras-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mono-nunit-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mono-web-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mono-winforms-1.2.2-12.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
