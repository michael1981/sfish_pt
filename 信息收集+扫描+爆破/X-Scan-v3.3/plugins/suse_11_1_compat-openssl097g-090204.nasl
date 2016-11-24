
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40203);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.1 Security Update:  compat-openssl097g (2009-02-04)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for compat-openssl097g");
 script_set_attribute(attribute: "description", value: "This update improves the verification of return values.
Prior to this udpate it was possible to bypass the
certification chain checks of openssl. (CVE-2008-5077)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for compat-openssl097g");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=459468");
script_end_attributes();

 script_cve_id("CVE-2008-5077");
script_summary(english: "Check for the compat-openssl097g package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"compat-openssl097g-0.9.7g-146.9.1", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compat-openssl097g-0.9.7g-146.9.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"compat-openssl097g-32bit-0.9.7g-146.9.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
