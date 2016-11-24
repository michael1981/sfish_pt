
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27247);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  gpg security update (gpg-2388)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gpg-2388");
 script_set_attribute(attribute: "description", value: "- Specially crafted files could overflow a buffer when gpg
  was used
 in interactive mode (CVE-2006-6169).
- Specially crafted files could modify a function pointer
  and
 execute code this way (CVE-2006-6235).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch gpg-2388");
script_end_attributes();

script_cve_id("CVE-2006-6169", "CVE-2006-6235");
script_summary(english: "Check for the gpg-2388 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gpg-1.4.5-24.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gpg2-1.9.22-20.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
