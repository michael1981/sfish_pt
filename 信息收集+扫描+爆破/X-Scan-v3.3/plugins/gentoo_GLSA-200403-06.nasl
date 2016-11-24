# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-06.xml
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
 script_id(14457);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200403-06");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-06
(Multiple remote buffer overflow vulnerabilities in Courier)


    The vulnerabilities have been found in the \'SHIFT_JIS\' converter in
    \'shiftjis.c\' and \'ISO2022JP\' converter in \'so2022jp.c\'. An attacker may
    supply Unicode characters that exceed BMP (Basic Multilingual Plane) range,
    causing an overflow.
  
Impact

    An attacker without privileges may exploit this vulnerability remotely, allowing arbitrary code to be executed in order to gain unauthorized access.
  
Workaround

    While a workaround is not currently known for this issue, all users are
    advised to upgrade to the latest version of the affected packages.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to current versions of the affected packages:
    # emerge sync
    # emerge -pv ">=net-mail/courier-imap-3.0.0"
    # emerge ">=net-mail/courier-imap-3.0.0"
    # ** Or; depending on your installation... **
    # emerge -pv ">=mail-mta/courier-0.45"
    # emerge ">=mail-mta/courier-0.45"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/9845');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0224');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-06] Multiple remote buffer overflow vulnerabilities in Courier');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple remote buffer overflow vulnerabilities in Courier');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-mta/courier", unaffected: make_list("ge 0.45"), vulnerable: make_list("lt 0.45")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-mail/courier-imap", unaffected: make_list("ge 3.0.0"), vulnerable: make_list("lt 3.0.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
