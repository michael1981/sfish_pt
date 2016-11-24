# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-09.xml
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
 script_id(14460);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200403-09");
 script_cve_id("CVE-2003-1023");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-09
(Buffer overflow in Midnight Commander)


    A stack-based buffer overflow has been found in Midnight Commander\'s
    virtual filesystem.
  
Impact

    This overflow allows an attacker to run arbitrary code on the user\'s
    computer during the symlink conversion process.
  
Workaround

    While a workaround is not currently known for this issue, all users are
    advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the current version of the affected package:
    # emerge sync
    # emerge -pv ">=app-misc/mc-4.6.0-r5"
    # emerge ">=app-misc/mc-4.6.0-r5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2003-1023');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-09] Buffer overflow in Midnight Commander');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Buffer overflow in Midnight Commander');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-misc/mc", unaffected: make_list("ge 4.6.0-r5"), vulnerable: make_list("le 4.6.0-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
