
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40254);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.1 Security Update:  kvm (2009-01-12)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for kvm");
 script_set_attribute(attribute: "description", value: "Rogue VNC clients could make the built in VNC server of kvm
run into an infinite loop (CVE-2008-2382)

An off-by-one bug limited the length of VNC passwords to
seven instead of eight (CVE-2008-5714)

Virtualized guests could potentially execute code on the
host by triggering a buffer overflow in the network
emulation code via large ethernet frames (CVE-2007-5729)

Virtualized guests could potentially execute code on the
host by triggering a heap based buffer overflow in the
Cirrus Graphics card emulation (CVE-2007-1320).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for kvm");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=448551");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=464142");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=464141");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=252519");
script_end_attributes();

 script_cve_id("CVE-2007-1320", "CVE-2007-5729", "CVE-2008-2382", "CVE-2008-5714");
script_summary(english: "Check for the kvm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kvm-78-6.5.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kvm-78-6.5.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
