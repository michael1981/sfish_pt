
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32419);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0061: setroubleshoot");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0061");
 script_set_attribute(attribute: "description", value: '
  Updated setroubleshoot packages that fix two security issues and several
  bugs are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The setroubleshoot packages provide tools to help diagnose SELinux
  problems. When AVC messages occur, an alert is generated that gives
  information about the problem, and how to create a resolution.

  A flaw was found in the way sealert wrote diagnostic messages to a
  temporary file. A local unprivileged user could perform a symbolic link
  attack, and cause arbitrary files, writable by other users, to be
  overwritten when a victim runs sealert. (CVE-2007-5495)

  A flaw was found in the way sealert displayed records from the
  setroubleshoot database as unescaped HTML. An local unprivileged attacker
  could cause AVC denial events with carefully crafted process or file names,
  injecting arbitrary HTML tags into the logs, which could be used as a
  scripting attack, or to confuse the user running sealert. (CVE-2007-5496)

  Additionally, the following bugs have been fixed in these update packages:

  * in certain situations, the sealert process used excessive CPU. These
  alerts are now capped at a maximum of 30, D-Bus is used instead of polling,
  threads causing excessive wake-up have been removed, and more robust
  exception-handling has been added.

  * different combinations of the sealert \'-a\', \'-l\', \'-H\', and \'-v\' options
  did not work as documented.

  * the SETroubleShoot browser did not allow multiple entries to be deleted.

  * the SETroubleShoot browser did not display statements that displayed
  whether SELinux was using Enforcing or Permissive mode, particularly when
  warning about SELinux preventions.

  * in certain cases, the SETroubleShoot browser gave incorrect instructions
  regarding paths, and would not display the full paths to files.

  * adding an email recipient to the recipients option from the
  /etc/setroubleshoot/setroubleshoot.cfg file and then generating an SELinux
  denial caused a traceback error. The recipients option has been removed;
  email addresses are now managed through the SETroubleShoot browser by
  navigating to File -> Edit Email Alert List, or by editing the
  /var/lib/setroubleshoot/email_alert_recipients file.

  * the setroubleshoot browser incorrectly displayed a period between the
  httpd_sys_content_t context and the directory path.

  * on the PowerPC architecture, The get_credentials() function in
  access_control.py would generate an exception when it called the
  socket.getsockopt() function.

  * The code which handles path information has been completely rewritten so
  that assumptions on path information which were misleading are no longer
  made. If the path information is not present, it will be presented as
  "<Unknown>".

  * setroubleshoot had problems with non-English locales under certain
  circumstances, possibly causing a python traceback, an sealert window
  pop-up containing an error, a "RuntimeError: maximum recursion depth
  exceeded" error after a traceback, or a "UnicodeEncodeError" after a traceback.

  * sealert ran even when SELinux was disabled, causing "attempt to open
  server connection failed" errors. Sealert now checks whether SELinux is
  enabled or disabled.

  * the database setroubleshoot maintains was world-readable. The
  setroubleshoot database is now mode 600, and is owned by the root user and
  group.

  * setroubleshoot did not validate requests to set AVC filtering options for
  users. In these updated packages, checks ensure that requests originate
  from the filter owner.

  * the previous setroubleshoot packages required a number of GNOME packages
  and libraries. setroubleshoot has therefore been split into 2 packages:
  setroubleshoot and setroubleshoot-server.

  * a bug in decoding the audit field caused an "Input is not proper UTF-8,
  indicate encoding!" error message. The decoding code has been rewritten.

  * a file name mismatch in the setroubleshoot init script would cause a
  failure to shut down.

  Users of setroubleshoot are advised to upgrade to these updated packages,
  which resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0061.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5495", "CVE-2007-5496");
script_summary(english: "Check for the version of the setroubleshoot packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"setroubleshoot-2.0.5-3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"setroubleshoot-plugins-2.0.4-2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"setroubleshoot-server-2.0.5-3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
