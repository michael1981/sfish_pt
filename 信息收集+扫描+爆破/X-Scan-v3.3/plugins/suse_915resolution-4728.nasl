
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29911);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for Intel i810 chips (915resolution-4728)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch 915resolution-4728");
 script_set_attribute(attribute: "description", value: "The drm i915 component in the kernel before 2.6.22.2, when
used with i965G and later chips ets, allows local users
with access to an X11 session and Direct Rendering Manager
(DRM) t o write to arbitrary memory locations and gain
privileges via a crafted batchbuffer.

This update also provides the latests i810 driver stack,
which includes fixes for FnFx handling (enables switching
from internal to external and internal monitor on Laptops)

");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch 915resolution-4728");
script_end_attributes();

script_summary(english: "Check for the 915resolution-4728 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"915resolution-0.5.2.1-1.2.5", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-Mesa-6.4.2.2-1.2.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-bigsmp-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-debug-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-default-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-xenpae-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-bigsmp-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-debug-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-default-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-xenpae-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-xorg-x11-6.9.0.2-2.2.12", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-7.1-125.41.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-gui-1.7-125.41.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-ident-1.7-125.42.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-libsax-7.1-125.41.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-libsax-devel-7.1-125.41.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-libsax-java-7.1-125.41.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-libsax-perl-7.1-125.41.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-libsax-python-7.1-125.41.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-tools-2.7-125.41.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"915resolution-0.5.2.1-1.2.5", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-Mesa-6.4.2.2-1.2.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-bigsmp-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-default-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-agpgart-kmp-xenpae-1.2_2.6.16.54_0.2.3-1.2.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-bigsmp-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-default-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-drm-kmp-xenpae-1.2_2.6.16.54_0.2.3-1.2.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"intel-i810-xorg-x11-6.9.0.2-2.2.12", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-7.1-125.41.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-gui-1.7-125.41.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-ident-1.7-125.42.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-libsax-7.1-125.41.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-libsax-csharp-7.1-121.41.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-libsax-perl-7.1-125.41.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"sax2-tools-2.7-125.41.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
