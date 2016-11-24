
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-854
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24159);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 4 2006-854: openmotif");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-854 (openmotif)");
 script_set_attribute(attribute: "description", value: "This is the Open Motif 2.2.3 runtime environment. It includes the
Motif shared libraries, needed to run applications which are dynamically
linked against Motif, and the Motif Window Manager 'mwm'.



Update information :

* Wed Mar 29 2006 Thomas Woerner <twoerner redhat com> 2.2.3-10.FC4.2
- fixed CVE-2005-3964: libUil buffer overflows (#174815)

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2005-3964");
script_summary(english: "Check for the version of the openmotif package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"openmotif-2.2.3-10.FC4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
