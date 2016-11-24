# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-12.xml
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
 script_id(14568);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200408-12");
 script_cve_id("CVE-2004-0500");
 script_xref(name: "OSVDB", value: "8382");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-12
(Gaim: MSN protocol parsing function buffer overflow)


    Sebastian Krahmer of the SuSE Security Team has discovered a remotely
    exploitable buffer overflow vulnerability in the code handling MSN
    protocol parsing.
  
Impact

    By sending a carefully-crafted message, an attacker may execute
    arbitrary code with the permissions of the user running Gaim.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Gaim.
  
');
script_set_attribute(attribute:'solution', value: '
    All Gaim users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-im/gaim-0.81-r1"
    # emerge ">=net-im/gaim-0.81-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.osvdb.org/displayvuln.php?osvdb_id=8382');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0500');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-12] Gaim: MSN protocol parsing function buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: MSN protocol parsing function buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 0.81-r1"), vulnerable: make_list("le 0.81")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
