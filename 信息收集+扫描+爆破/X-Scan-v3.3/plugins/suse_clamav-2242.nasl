
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27176);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  clamav: Upgrade to version 0.88.6 (clamav-2242)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch clamav-2242");
 script_set_attribute(attribute: "description", value: "The virus scan engine ClamAV was update to version 0.88.6.

Following issues are fixed by this update:

- freshclam: apply timeout patch from Everton da Silva
  Marques (new options: ConnectTimeout and ReceiveTimeout)
- clamd: change stack size at the right place (closes
  clamav bug#103)
- libclamav/petite.c: sanity check the number of rebuilt
  sections (speeds up handling of malformed files)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch clamav-2242");
script_end_attributes();

script_summary(english: "Check for the clamav-2242 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"clamav-0.88.6-1.4", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
