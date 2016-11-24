
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29573);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for ruby (ruby-4702)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ruby-4702");
 script_set_attribute(attribute: "description", value: "This update of ruby improves the SSL certificate
verification process. (CVE-2007-5162, CVE-2007-5770)  Prior
to this update it was possible to intercept SSL traffic
with a man-in-the-middle attack.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch ruby-4702");
script_end_attributes();

script_cve_id("CVE-2007-5162", "CVE-2007-5770");
script_summary(english: "Check for the ruby-4702 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"ruby-1.8.4-17.16", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
