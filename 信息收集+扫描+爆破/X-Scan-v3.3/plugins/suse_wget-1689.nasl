
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27476);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  wget: Security update solving terminal escape codes problems (wget-1689)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch wget-1689");
 script_set_attribute(attribute: "description", value: "This update fixes a security in wget, where evil servers
could send terminal escape codes to the user calling wget.
This would only affect interactive sessions. (CVE-2004-1488)

Additionaly a previous '.file' fix was found to be buggy
and replaced. This bug could lead to '.directories' not
being retrievable and '_files'  being overwritten.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch wget-1689");
script_end_attributes();

script_cve_id("CVE-2004-1488");
script_summary(english: "Check for the wget-1689 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"wget-1.10.2-15.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
