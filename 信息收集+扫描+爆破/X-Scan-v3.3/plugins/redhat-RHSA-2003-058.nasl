
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12366);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2003-058: shadow");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-058");
 script_set_attribute(attribute: "description", value: '
  Updated shadow-utils packages are now available. These updated packages
  correct a bug that caused the useradd tool to create mail spools with
  incorrect permissions.

  The shadow-utils package includes programs for converting UNIX password
  files to the shadow password format, plus programs for managing user and
  group accounts. One of these programs is useradd, which is used to create
  or update new user information.

  When creating a user account, the version of useradd included in Red Hat
  packages creates a mail spool file with incorrectly-set group ownership.
  Instead of setting the file\'s group ownership to the "mail" group, it is
  set to the user\'s primary group.

  On systems where other users share the same primary group, this would allow
  those users to be able to read and write other user mailboxes.

  These errata packages contain an updated patch to useradd. Where a mail
  group exists, mailboxes will be created with group mail having read and
  write permissions. Otherwise the mailbox will be created without group
  read and write permissions.

  All users are advised to upgrade to these updated packages and also to
  check the /var/spool/mail directory to ensure that mailboxes have correct
  permissions.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-058.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1509");
script_summary(english: "Check for the version of the shadow packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"shadow-utils-20000902-9.7", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
