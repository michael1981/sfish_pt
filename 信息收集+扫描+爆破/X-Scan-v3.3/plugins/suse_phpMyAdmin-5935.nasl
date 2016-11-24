
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35449);
 script_version ("$Revision: 1.4 $");
 script_name(english: "SuSE Security Update:  phpMyAdmin: security upgrade to version 2.11.9.4 (phpMyAdmin-5935)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch phpMyAdmin-5935");
 script_set_attribute(attribute: "description", value: "This is a version upgrade to phpMyAdmin 2.11.9.4 to fix
various security bugs.  (CVE-2008-2960, CVE-2008-3197,
CVE-2008-1149, CVE-2008-1567, CVE-2008-1924, CVE-2008-4096,
CVE-2008-4326, CVE-2008-5621, CVE-2008-5622)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch phpMyAdmin-5935");
script_end_attributes();

 script_cve_id("CVE-2008-1149", "CVE-2008-1567", "CVE-2008-1924", "CVE-2008-2960", "CVE-2008-3197", "CVE-2008-4096", "CVE-2008-4326", "CVE-2008-5621");
script_summary(english: "Check for the phpMyAdmin-5935 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"phpMyAdmin-2.11.9.4-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
