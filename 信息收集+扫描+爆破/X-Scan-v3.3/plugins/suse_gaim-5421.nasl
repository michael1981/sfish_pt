
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34192);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  gaim security update (gaim-5421)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gaim-5421");
 script_set_attribute(attribute: "description", value: "- specially crafted MSN SLP messages could cause an integer
  overflow in gaim. Attackers could potentially exploit
  that to execute arbitrary code (CVE-2008-2927).

Additionally a problem was fixed that prevented gaim
clients from connecting to the ICQ network after a server
change on July 1st 2008.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gaim-5421");
script_end_attributes();

script_cve_id("CVE-2008-2927");
script_summary(english: "Check for the gaim-5421 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gaim-1.5.0-88", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gaim-devel-1.5.0-88", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
