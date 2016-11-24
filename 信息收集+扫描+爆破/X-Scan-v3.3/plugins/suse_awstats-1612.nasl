
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27163);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  awstats: security update for remote command injection (awstats-1612)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch awstats-1612");
 script_set_attribute(attribute: "description", value: "This update fixes remote code execution vulnerabilities in 
awstats.  Since backporting awstats fixes is error prone we 
have upgraded it to upstream version 6.6, which also 
includes new features.  Security issues fixed:  - 
CVE-2006-2237: missing sanitizing of the 'migrate' 
parameter. #173041 - CVE-2006-2644: missing sanitizing of 
the 'configdir' parameter. #173041 - Make sure open() only 
opens files for read/write by adding explicit < and >.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch awstats-1612");
script_end_attributes();

script_cve_id("CVE-2006-2237", "CVE-2006-2644");
script_summary(english: "Check for the awstats-1612 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"awstats-6.6-0.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
