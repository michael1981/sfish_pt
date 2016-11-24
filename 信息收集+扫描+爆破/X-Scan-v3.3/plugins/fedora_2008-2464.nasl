
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2464
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31434);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-2464: dovecot");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2464 (dovecot)");
 script_set_attribute(attribute: "description", value: "Dovecot is an IMAP server for Linux/UNIX-like systems, written with security
primarily in mind.  It also contains a small POP3 server.  It supports mail
in either of maildir or mbox formats.

The SQL drivers and authentication plugins are in their subpackages.

-
Update Information:

This update upgrades dovecot from version 1.0.10 to 1.0.13.  Besides bug fixes,
two security issues were fixed upstream in version 1.0.11 and 1.0.13.
CVE-2008-1199  If Dovecot was configured with mail_extra_groups = mail, users
having shell access to IMAP server could use this flaw to read, modify or delet
e
mails of other users stored in inbox files in /var/mail.  /var/mail directory i
s
mail-group writable and user inbox files are by default created by useradd with
permission 660, <user>:mail.    No mail_extra_groups is set by default, hence
default Fedora configuration was not affected by this problem.  If your
configuration sets mail_extra_groups, see new options mail_privileged_group and
mail_access_groups introduced in Dovecot 1.0.11.  (mail_extra_groups is still
accepted, but is deprecated now)    CVE-2008-1218  On Dovecot versions 1.0.11
and newer, it was possible to gain password-less login via passwords with tab
characters, which were not filtered properly.    Dovecot versions in Fedora wer
e
not affected by this unauthorized login flaw, but only by a related minor memor
y
leak in dovecot-auth worker process.  See referenced bugzilla for further
details about this flaw.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1199", "CVE-2008-1218");
script_summary(english: "Check for the version of the dovecot package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"dovecot-1.0.13-6.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
