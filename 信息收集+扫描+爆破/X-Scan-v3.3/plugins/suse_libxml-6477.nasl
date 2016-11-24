
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42020);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  libxml: XML parsing vulnerability (libxml-6477)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libxml-6477");
 script_set_attribute(attribute: "description", value: "This update of libxml does not use pointers after they were
freed anymore. (CVE-2009-2416)  Additionally a stack-based
buffer overflow was fixed while parsing the root XML
document. (CVE-2009-2414)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libxml-6477");
script_end_attributes();

script_cve_id("CVE-2009-2416", "CVE-2009-2414");
script_summary(english: "Check for the libxml-6477 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libxml-1.8.17-450.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libxml-32bit-1.8.17-450.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libxml-64bit-1.8.17-450.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libxml-devel-1.8.17-450.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
