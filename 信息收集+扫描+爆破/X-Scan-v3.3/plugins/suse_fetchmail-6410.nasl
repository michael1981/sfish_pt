
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41998);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  fetchmail: fix for security issue regarding SSL cert validatin (fetchmail-6410)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch fetchmail-6410");
 script_set_attribute(attribute: "description", value: "This update of fetchmail improves SSL certificate
validation to stop possible man-in-the-middle attacks by
inserting \0-character in the certificate's subject name.
(CVE-2009-2666)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch fetchmail-6410");
script_end_attributes();

script_cve_id("CVE-2009-2666");
script_summary(english: "Check for the fetchmail-6410 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"fetchmail-6.3.8-57.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.3.8-57.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
