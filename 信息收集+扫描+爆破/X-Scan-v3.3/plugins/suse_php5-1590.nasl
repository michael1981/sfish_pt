
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27389);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  php5 security update (php5-1590)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch php5-1590");
 script_set_attribute(attribute: "description", value: "This update fixes the following security issues:  - invalid 
charactes in session names were not blocked  - a bug in 
zend_hash_del() allowed attackers to prevent unsetting of 
some variables  - bugs in the substr_compare()  and 
wordwrap function could crash php (CVE-2006-1991, 
CVE-2006-1990)  - a memory leak in the imagecreatefromgif() 
function
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch php5-1590");
script_end_attributes();

script_cve_id("CVE-2006-1991", "CVE-2006-1990");
script_summary(english: "Check for the php5-1590 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"apache2-mod_php5-5.1.2-29.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"php5-5.1.2-29.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"php5-gd-5.1.2-29.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
