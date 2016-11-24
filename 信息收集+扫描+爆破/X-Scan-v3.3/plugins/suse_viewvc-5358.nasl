
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33788);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  viewvc: multiple vulnerabilities fixed (viewvc-5358)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch viewvc-5358");
 script_set_attribute(attribute: "description", value: "This update of viewvc fixes multiple vulnerabilities.
- CVE-2008-1290: list CVS or SVN commits on 'all-forbidden'
  files
- CVE-2008-1291: directly access hidden CVSROOT folders
- CVE-2008-1292: expose restricted content via the revision
  view, the log history, or the diff view
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch viewvc-5358");
script_end_attributes();

script_cve_id("CVE-2008-1290", "CVE-2008-1291", "CVE-2008-1292");
script_summary(english: "Check for the viewvc-5358 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"viewvc-1.0.4-25.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
