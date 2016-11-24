# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-11.xml
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
 script_id(14497);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200405-11");
 script_cve_id("CVE-2004-0411");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-11
(KDE URI Handler Vulnerabilities)


    The telnet, rlogin, ssh and mailto URI handlers in KDE do not check for \'-\'
    at the beginning of the hostname passed. By crafting a malicious URI and
    entice an user to click on it, it is possible to pass an option to the
    programs started by the handlers (typically telnet, kmail...).
  
Impact

    If the attacker controls the options passed to the URI handling programs,
    it becomes possible for example to overwrite arbitrary files (possibly
    leading to denial of service), to open kmail on an attacker-controlled
    remote display or with an alternate configuration file (possibly leading to
    control of the user account).
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to a corrected version of kdelibs.
  
');
script_set_attribute(attribute:'solution', value: '
    Users of KDE 3.1 should upgrade to the corrected version of kdelibs:
    # emerge sync
    # emerge -pv "=kde-base/kdelibs-3.1.5-r1"
    # emerge "=kde-base/kdelibs-3.1.5-r1"
    Users of KDE 3.2 should upgrade to the latest available version of kdelibs:
    # emerge sync
    # emerge -pv ">=kde-base/kdelibs-3.2.2-r1"
    # emerge ">=kde-base/kdelibs-3.2.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0411');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-11] KDE URI Handler Vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDE URI Handler Vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("ge 3.2.2-r1", "eq 3.1.5-r1"), vulnerable: make_list("le 3.2.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
