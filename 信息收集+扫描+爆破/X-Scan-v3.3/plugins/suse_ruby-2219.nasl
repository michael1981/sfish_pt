
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27422);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  ruby: Fixed denial of service problem in CGI multipart parsing (ruby-2219)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ruby-2219");
 script_set_attribute(attribute: "description", value: "A denial of service problem in the CGI multipart parsing of
'ruby' was fixed, which could have allowed remote attackers
to affect a denial of service attack against ruby based
webservices. (CVE-2006-5467)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch ruby-2219");
script_end_attributes();

script_cve_id("CVE-2006-5467");
script_summary(english: "Check for the ruby-2219 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ruby-1.8.4-17.8", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
