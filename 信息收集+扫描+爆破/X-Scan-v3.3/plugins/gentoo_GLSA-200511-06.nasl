# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-06.xml
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
 script_id(20156);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200511-06");
 script_cve_id("CVE-2005-3088");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-06
(fetchmail: Password exposure in fetchmailconf)


    Thomas Wolff discovered that fetchmailconf opens the configuration
    file with default permissions, writes the configuration to it, and only
    then restricts read permissions to the owner.
  
Impact

    A local attacker could exploit the race condition to retrieve
    sensitive information like IMAP/POP passwords.
  
Workaround

    Run "umask 077" to temporarily strengthen default permissions,
    then run "fetchmailconf" from the same shell.
  
');
script_set_attribute(attribute:'solution', value: '
    All fetchmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/fetchmail-6.2.5.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://fetchmail.berlios.de/fetchmail-SA-2005-02.txt');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3088');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-06] fetchmail: Password exposure in fetchmailconf');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'fetchmail: Password exposure in fetchmailconf');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/fetchmail", unaffected: make_list("ge 6.2.5.2-r1"), vulnerable: make_list("lt 6.2.5.2-r1")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
