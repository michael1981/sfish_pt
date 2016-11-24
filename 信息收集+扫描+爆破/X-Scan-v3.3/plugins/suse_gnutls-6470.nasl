
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41517);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for GnuTLS (gnutls-6470)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gnutls-6470");
 script_set_attribute(attribute: "description", value: "This update of gnutls improves the verification of the
domain/subject names in a SSL certificate. CVE-2009-2417
has been assigned to this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gnutls-6470");
script_end_attributes();

script_cve_id("CVE-2009-2417");
script_summary(english: "Check for the gnutls-6470 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"gnutls-1.2.10-13.19", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gnutls-devel-1.2.10-13.19", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
