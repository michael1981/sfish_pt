
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38180);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  clamav: clamav 0.95.1 fixes two security issues (clamav-6201)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch clamav-6201");
 script_set_attribute(attribute: "description", value: "This clamav version upgrade to 0.95.1 fixes a buffer
overflow error in the cli_url_canon() function
(CVE-2009-1372) and a denial of service condition occuring
while parsing malformed UPack archives (CVE-2009-1371).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch clamav-6201");
script_end_attributes();

script_cve_id("CVE-2009-1372", "CVE-2009-1371");
script_summary(english: "Check for the clamav-6201 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"clamav-0.95.1-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"clamav-db-0.95.1-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
