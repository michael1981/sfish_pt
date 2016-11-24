
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41593);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for udev (udev-6153)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch udev-6153");
 script_set_attribute(attribute: "description", value: "This update fixes a local privilege escalation in udev.

CVE-2009-1185: udev did not check the origin of the netlink
messages. A local attacker could fake device create events
and so gain root privileges.

It also fixes three bugs:
- Fixup persistent symlinks for tapes (bnc#446534)
- Fixup broken ATA compability links (bnc#447995)
- Add by-path links for tapes (bnc#478132)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch udev-6153");
script_end_attributes();

script_cve_id("CVE-2009-1185");
script_summary(english: "Check for the udev-6153 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"udev-085-30.52", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
