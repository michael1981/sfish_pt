#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19666);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Fedora Core 3 2005-808: openmotif";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-808 (openmotif).

This is the Open Motif 2.2.1 runtime environment. It includes the
Motif shared libraries, needed to run applications which are dynamically
linked against Motif, and the Motif Window Manager 'mwm'.


* Mon Apr  4 2005 Thomas Woerner <twoerner redhat com> 2.2.3-9.FC3.1
- fixed possible libXpm overflows (#151642)
- Upstream Fix: Multiscreen mode
- Upstream Fix: Crash when restarting by a session manager (motifzone#1193)
- Upstream Fix: Crash when duplicating a window menu containing f.circle_up
(motifzone#1202)
- fixed divide by zero error in ComputeVizCount() (#144420)
- Xpmcreate: define LONG64 on 64 bit architectures (#143689)

* Mon Nov 29 2004 Thomas Woerner <twoerner redhat com> 2.2.3-6.FC3.2
- allow to write XPM files with absolute path names again (#140815)" );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the openmotif package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openmotif-2.2.3-9.FC3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-9.FC3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
