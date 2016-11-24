
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34959);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  horde: multiple vulnerabilities fixed (horde-5791)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch horde-5791");
 script_set_attribute(attribute: "description", value: "This update of horde fixes the following vulnerabilities:
- CVE-2008-1284: directory traversal allows authenticated
  user to access and execute arbitrary files
- CVE-2008-3330: remotely exploitable XSS
- CVE-2008-3824: remotely exploitable XSS
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch horde-5791");
script_end_attributes();

script_cve_id("CVE-2008-1284", "CVE-2008-3330", "CVE-2008-3824");
script_summary(english: "Check for the horde-5791 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"horde-3.1.4-55.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
