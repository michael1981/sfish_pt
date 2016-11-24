
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32422);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2008-0295: vsftpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0295");
 script_set_attribute(attribute: "description", value: '
  An updated vsftpd package that fixes a security issue and several bugs is
  now available for Red Hat Enterprise Linux 5.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The vsftpd package includes a Very Secure File Transfer Protocol (FTP)
  daemon.

  A memory leak was discovered in the vsftpd daemon. An attacker who is able
  to connect to an FTP service, either as an authenticated or anonymous user,
  could cause vsftpd to allocate all available memory if the "deny_file"
  option was enabled in vsftpd.conf. (CVE-2007-5962)

  As well, this updated package fixes following bugs:

  * a race condition could occur even when the "lock_upload_files" option is
  set. When uploading two files simultaneously, the result was a combination
  of the two files. This resulted in uploaded files becoming corrupted. In
  these updated packages, uploading two files simultaneously will result in a
  file that is identical to the last uploaded file.

  * when the "userlist_enable" option is used, failed log in attempts as a
  result of the user not being in the list of allowed users, or being in the
  list of denied users, will not be logged. In these updated packages, a new
  "userlist_log=YES" option can be configured in vsftpd.conf, which will log
  failed log in attempts in these situations.

  * vsftpd did not support usernames that started with an underscore or a
  period character. Usernames starting with an underscore or a period are
  supported in these updated packages.

  * using wildcards in conjunction with the "ls" command did not return all
  the file names it should. For example, if you FTPed into a directory
  containing three files -- A1, A21 and A11 -- and ran the "ls *1" command,
  only the file names A1 and A21 were returned. These updated packages use
  greedier code that continues to speculatively scan for items even after
  matches have been found.

  * when the "user_config_dir" option is enabled in vsftpd.conf, and the
  user-specific configuration file did not exist, the following error
  occurred after a user entered their password during the log in process:

  500 OOPS: reading non-root config file

  This has been resolved in this updated package.

  All vsftpd users are advised to upgrade to this updated package, which
  resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0295.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5962");
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

if ( rpm_check( reference:"vsftpd-2.0.5-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
