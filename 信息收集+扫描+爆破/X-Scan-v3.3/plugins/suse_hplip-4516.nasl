
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27267);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  hplip security update (hplip-4516)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch hplip-4516");
 script_set_attribute(attribute: "description", value: "The deamon 'hpssd' could be exploited by users to execute
arbitrary commands as root. hpssd only runs on systems that
have HP all-in-one devices configured. In the default
configuration the problem is not remotely exploitable as
hpssd only listens on local interfaces (CVE-2007-5208).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch hplip-4516");
script_end_attributes();

script_cve_id("CVE-2007-5208");
script_summary(english: "Check for the hplip-4516 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"hplip-2.7.7-37.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"hplip-hpijs-2.7.7-37.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
