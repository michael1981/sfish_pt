
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31390);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  asterisk security update (asterisk-5062)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch asterisk-5062");
 script_set_attribute(attribute: "description", value: "Attackers could bypass host based authentication by using a
valid username (CVE-2007-6430)

Attackers could inject SQL commands under certain
circumstances if 'cdr_pgsql' was used (CVE-2007-6170)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch asterisk-5062");
script_end_attributes();

script_cve_id("CVE-2007-6430", "CVE-2007-6170");
script_summary(english: "Check for the asterisk-5062 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"asterisk-1.2.13-27", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"asterisk-alsa-1.2.13-27", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"asterisk-odbc-1.2.13-27", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"asterisk-pgsql-1.2.13-27", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"asterisk-spandsp-1.2.13-27", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"asterisk-zaptel-1.2.13-27", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
