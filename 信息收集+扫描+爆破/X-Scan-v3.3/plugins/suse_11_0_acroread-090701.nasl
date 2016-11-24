
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39908);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.0 Security Update:  acroread (2009-07-01)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for acroread");
 script_set_attribute(attribute: "description", value: "This update of acroread fixes the following vulnerabilities:
- CVE-2009-1855: stack overflow that could lead to code
  execution
- CVE-2009-1856: integer overflow with potential to lead to
  arbitrary code execution
- CVE-2009-1857: memory corruption with potential to lead
  to arbitrary code execution
- CVE-2009-1858: memory corruption with potential to lead
  to arbitrary code execution
- CVE-2009-1859: memory corruption with potential to lead
  to arbitrary code execution
- CVE-2009-0198: memory corruption with potential to lead
  to arbitrary code execution
- CVE-2009-0509, CVE-2009-0510 CVE-2009-0511,
  CVE-2009-0512:  heap overflow that could lead to code
  execution
- CVE-2009-1861: heap overflow that could lead to code
  execution
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for acroread");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=511566");
script_end_attributes();

 script_cve_id("CVE-2009-0198", "CVE-2009-0509", "CVE-2009-0510", "CVE-2009-0511", "CVE-2009-0512", "CVE-2009-1855", "CVE-2009-1856", "CVE-2009-1857", "CVE-2009-1858", "CVE-2009-1859", "CVE-2009-1861");
script_summary(english: "Check for the acroread package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"acroread-8.1.6-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
