
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27250);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  gpg2: This update fixes a segmentaion fault (gpg2-1956)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gpg2-1956");
 script_set_attribute(attribute: "description", value: "This update of gpg2 fixes an segmentation fault when using
the--no-armor option. This failure leads to a
denial-of-service attack and may be used execute arbitrary
code. (CVE-2006-3746)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gpg2-1956");
script_end_attributes();

script_cve_id("CVE-2006-3746");
script_summary(english: "Check for the gpg2-1956 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gpg2-1.9.18-17.8", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
