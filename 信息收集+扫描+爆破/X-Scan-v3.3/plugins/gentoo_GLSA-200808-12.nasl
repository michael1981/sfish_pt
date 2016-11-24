# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200808-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(33891);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200808-12");
 script_cve_id("CVE-2008-2936", "CVE-2008-2937");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200808-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200808-12
(Postfix: Local privilege escalation vulnerability)


    Sebastian Krahmer of SuSE has found that Postfix allows to deliver mail
    to root-owned symlinks in an insecure manner under certain conditions.
    Normally, Postfix does not deliver mail to symlinks, except to
    root-owned symlinks, for compatibility with the systems using symlinks
    in /dev like Solaris. Furthermore, some systems like Linux allow to
    hardlink a symlink, while the POSIX.1-2001 standard requires that the
    symlink is followed. Depending on the write permissions and the
    delivery agent being used, this can lead to an arbitrary local file
    overwriting vulnerability (CVE-2008-2936). Furthermore, the Postfix
    delivery agent does not properly verify the ownership of a mailbox
    before delivering mail (CVE-2008-2937).
  
Impact

    The combination of these features allows a local attacker to hardlink a
    root-owned symlink such that the newly created symlink would be
    root-owned and would point to a regular file (or another symlink) that
    would be written by the Postfix built-in local(8) or virtual(8)
    delivery agents, regardless the ownership of the final destination
    regular file. Depending on the write permissions of the spool mail
    directory, the delivery style, and the existence of a root mailbox,
    this could allow a local attacker to append a mail to an arbitrary file
    like /etc/passwd in order to gain root privileges.
    The default configuration of Gentoo Linux does not permit any kind of
    user privilege escalation.
    The second vulnerability (CVE-2008-2937) allows a local attacker,
    already having write permissions to the mail spool directory which is
    not the case on Gentoo by default, to create a previously nonexistent
    mailbox before Postfix creates it, allowing to read the mail of another
    user on the system.
  
Workaround

    The following conditions should be met in order to be vulnerable to
    local privilege escalation.
    The mail delivery style is mailbox, with the Postfix built-in
    local(8) or virtual(8) delivery agents.
    The mail spool directory (/var/spool/mail) is user-writeable.
    The user can create hardlinks pointing to root-owned symlinks
    located in other directories.
    Consequently, each one of the following workarounds is efficient.
    Verify that your /var/spool/mail directory is not writeable by a
    user. Normally on Gentoo, only the mail group has write access, and no
    end-user should be granted the mail group ownership.
    Prevent the local users from being able to create hardlinks
    pointing outside of the /var/spool/mail directory, e.g. with a
    dedicated partition.
    Use a non-builtin Postfix delivery agent, like procmail or
    maildrop.
    Use the maildir delivery style of Postfix ("home_mailbox=Maildir/"
    for example).
    Concerning the second vulnerability, check the write permissions of
    /var/spool/mail, or check that every Unix account already has a
    mailbox, by using Wietse Venema\'s Perl script available in the official
    advisory.
  
');
script_set_attribute(attribute:'solution', value: '
    All Postfix users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/postfix-2.5.3-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2936');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2937');
script_set_attribute(attribute: 'see_also', value: 'http://article.gmane.org/gmane.mail.postfix.announce/110');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200808-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200808-12] Postfix: Local privilege escalation vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Postfix: Local privilege escalation vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-mta/postfix", unaffected: make_list("rge 2.4.7-r1", "ge 2.5.3-r1", "rge 2.4.8", "ge 2.4.9"), vulnerable: make_list("lt 2.5.3-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
