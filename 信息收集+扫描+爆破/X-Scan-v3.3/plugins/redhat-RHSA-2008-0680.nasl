
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33582);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0680: vsftpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0680");
 script_set_attribute(attribute: "description", value: '
  An updated vsftpd package that fixes a security issue and various bugs is
  now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  vsftpd (Very Secure File Transfer Protocol (FTP) daemon) is a secure FTP
  server for Linux and Unix-like systems.

  The version of vsftpd as shipped in Red Hat Enterprise Linux 4 when used in
  combination with Pluggable Authentication Modules (PAM) had a memory leak
  on an invalid authentication attempt. Since vsftpd prior to version 2.0.5
  allows any number of invalid attempts on the same connection this memory
  leak could lead to an eventual DoS. (CVE-2008-2375)

  This update mitigates this security issue by including a backported patch
  which terminates a session after a given number of failed log in attempts.
  The default number of attempts is 3 and this can be configured using the
  "max_login_fails" directive.

  This package also addresses the following bugs:

  * when uploading unique files, a bug in vsftpd caused the file to be saved
  with a suffix \'.1\' even when no previous file with that name existed. This
  issues is resolved in this package.

  * when vsftpd was run through the init script, it was possible for the init
  script to print an \'OK\' message, even though the vsftpd may not have
  started. The init script no longer produces a false verification with this
  update.

  * vsftpd only supported usernames with a maximum length of 32 characters.
  The updated package now supports usernames up to 128 characters long.

  * a system flaw meant vsftpd output could become dependent on the timing or
  sequence of other events, even when the "lock_upload_files" option was set.
  If a file, filename.ext, was being uploaded and a second transfer of the
  file, filename.ext, was started before the first transfer was finished, the
  resultant uploaded file was a corrupt concatenation of the latter upload
  and the tail of the earlier upload. With this updated package, vsftpd
  allows the earlier upload to complete before overwriting with the latter
  upload, fixing the issue.

  * the \'lock_upload_files\' option was not documented in the manual page. A
  new manual page describing this option is included in this package.

  * vsftpd did not support usernames that started with an underscore or a
  period character. These special characters are now allowed at the beginning
  of a username.

  * when storing a unique file, vsftpd could cause an error for some clients.
  This is rectified in this package.

  * vsftpd init script was found to not be Linux Standards Base compliant.
  This update corrects their exit codes to conform to the standard.

  All vsftpd users are advised to upgrade to this updated package, which
  resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0680.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2375");
script_summary(english: "Check for the version of the vsftpd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"vsftpd-2.0.1-6.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
