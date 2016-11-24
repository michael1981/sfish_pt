
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40840);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1364: gdm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1364");
 script_set_attribute(attribute: "description", value: '
  Updated gdm packages that fix a security issue and several bugs are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The GNOME Display Manager (GDM) is a configurable re-implementation of XDM,
  the X Display Manager. GDM allows you to log in to your system with the X
  Window System running, and supports running several different X sessions on
  your local machine at the same time.

  A flaw was found in the way the gdm package was built. The gdm package was
  missing TCP wrappers support, which could result in an administrator
  believing they had access restrictions enabled when they did not.
  (CVE-2009-2697)

  This update also fixes the following bugs:

  * the GDM Reference Manual is now included with the gdm packages. The
  gdm-docs package installs this document in HTML format in
  "/usr/share/doc/". (BZ#196054)

  * GDM appeared in English on systems using Telugu (te_IN). With this
  update, GDM has been localized in te_IN. (BZ#226931)

  * the Ctrl+Alt+Backspace sequence resets the X server when in runlevel 5.
  In previous releases, however, repeated use of this sequence prevented GDM
  from starting the X server as part of the reset process. This was because
  GDM sometimes did not notice the X server shutdown properly and would
  subsequently fail to complete the reset process. This update contains an
  added check to explicitly notify GDM whenever the X server is terminated,
  ensuring that resets are executed reliably. (BZ#441971)

  * the "gdm" user is now part of the "audio" group by default. This enables
  audio support at the login screen. (BZ#458331)

  * the gui/modules/dwellmouselistener.c source code contained incorrect
  XInput code that prevented tablet devices from working properly. This
  update removes the errant code, ensuring that tablet devices work as
  expected. (BZ#473262)

  * a bug in the XOpenDevice() function prevented the X server from starting
  whenever a device defined in "/etc/X11/xorg.conf" was not actually plugged
  in. This update wraps XOpenDevice() in the gdk_error_trap_pop() and
  gdk_error_trap_push() functions, which resolves this bug. This ensures that
  the X server can start properly even when devices defined in
  "/etc/X11/xorg.conf" are not plugged in. (BZ#474588)

  All users should upgrade to these updated packages, which resolve these
  issues. GDM must be restarted for this update to take effect. Rebooting
  achieves this, but changing the runlevel from 5 to 3 and back to 5 also
  restarts GDM.


');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1364.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2697");
script_summary(english: "Check for the version of the gdm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gdm-2.16.0-56.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gdm-docs-2.16.0-56.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
