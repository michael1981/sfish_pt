
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41381);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  cyrus-sasl (2009-05-14)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for cyrus-sasl");
 script_set_attribute(attribute: "description", value: "This update of cyrus-sasl improves the output of function
sasl_encode64() by appending a 0 for string termination.
The impact depends on the application that uses
sasl_encode64(). (CVE-2009-0688)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for cyrus-sasl");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=499104");
script_end_attributes();

 script_cve_id("CVE-2009-0688");
script_summary(english: "Check for the cyrus-sasl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"cyrus-sasl-2.1.22-182.20.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-crammd5-2.1.22-182.20.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-digestmd5-2.1.22-182.20.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-gssapi-2.1.22-182.20.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-otp-2.1.22-182.20.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-plain-2.1.22-182.20.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-2.1.22-182.20.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-crammd5-2.1.22-182.20.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-digestmd5-2.1.22-182.20.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-gssapi-2.1.22-182.20.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-plain-2.1.22-182.20.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
