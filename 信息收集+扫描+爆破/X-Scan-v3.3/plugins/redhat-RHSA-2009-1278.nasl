
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40836);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1278: lftp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1278");
 script_set_attribute(attribute: "description", value: '
  An updated lftp package that fixes one security issue and various bugs is
  now available for Red Hat Enterprise Linux 5.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  LFTP is a sophisticated file transfer program for the FTP and HTTP
  protocols. Like bash, it has job control and uses the readline library for
  input. It has bookmarks, built-in mirroring, and can transfer several files
  in parallel. It is designed with reliability in mind.

  It was discovered that lftp did not properly escape shell metacharacters
  when generating shell scripts using the "mirror --script" command. A
  mirroring script generated to download files from a malicious FTP server
  could allow an attacker controlling the FTP server to run an arbitrary
  command as the user running lftp. (CVE-2007-2348)

  This update also fixes the following bugs:

  * when using the "mirror" or "get" commands with the "-c" option, lftp did
  not check for some specific conditions that could result in the program
  becoming unresponsive, hanging and the command not completing. For example,
  when waiting for a directory listing, if lftp received a "226" message,
  denoting an empty directory, it previously ignored the message and kept
  waiting. With this update, these conditions are properly checked for and
  lftp no longer hangs when "-c" is used with "mirror" or "get". (BZ#422881)

  * when using the "put", "mput" or "reput" commands over a Secure FTP (SFTP)
  connection, specifying the "-c" option sometimes resulted in corrupted
  files of incorrect size. With this update, using these commands over SFTP
  with the "-c" option works as expected, and transferred files are no
  longer corrupted in the transfer process. (BZ#434294)

  * previously, LFTP linked to the OpenSSL library. OpenSSL\'s license is,
  however, incompatible with LFTP\'s GNU GPL license and LFTP does not include
  an exception allowing OpenSSL linking. With this update, LFTP links to the
  GnuTLS (GNU Transport Layer Security) library, which is released under the
  GNU LGPL license. Like OpenSSL, GnuTLS implements the SSL and TLS
  protocols, so functionality has not changed. (BZ#458777)

  * running "help mirror" from within lftp only presented a sub-set of the
  available options compared to the full list presented in the man page. With
  this update, running "help mirror" in lftp presents the same list of mirror
  options as is available in the Commands section of the lftp man page.
  (BZ#461922)

  * LFTP imports gnu-lib from upstream. Subsequent to gnu-lib switching from
  GNU GPLv2 to GNU GPLv3, the LFTP license was internally inconsistent, with
  LFTP licensed as GNU GPLv2 but portions of the package apparently licensed
  as GNU GPLv3 because of changes made by the gnu-lib import. With this
  update, LFTP itself switches to GNU GPLv3, resolving the inconsistency.
  (BZ#468858)

  * when the "ls" command was used within lftp to present a directory listing
  on a remote system connected to via HTTP, file names containing spaces were
  presented incorrectly. This update corrects this behavior. (BZ#504591)

  * the default alias "edit" did not define a default editor. If EDITOR was
  not set in advance by the system, lftp attempted to execute
  "~/.lftp/edit.tmp.$$" (which failed because the file is not set to
  executable). The edit alias also did not support tab-completion of file
  names and incorrectly interpreted file names containing spaces. The updated
  package defines a default editor (vi) in the absence of a system-defined
  EDITOR. The edit alias now also supports tab-completion and handles file
  names containing spaces correctly for both downloading and uploading.
  (BZ#504594)

  Note: This update upgrades LFTP from version 3.7.3 to upstream version
  3.7.11, which incorporates a number of further bug fixes to those noted
  above. For details regarding these fixes, refer to the
  "/usr/share/doc/lftp-3.7.11/NEWS" file after installing this update.
  (BZ#308721)

  All LFTP users are advised to upgrade to this updated package, which
  resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1278.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2348");
script_summary(english: "Check for the version of the lftp packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lftp-3.7.11-4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
