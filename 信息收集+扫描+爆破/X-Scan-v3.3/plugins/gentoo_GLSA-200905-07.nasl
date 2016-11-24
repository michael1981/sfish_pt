# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200905-07.xml
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
 script_id(38909);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200905-07");
 script_cve_id("CVE-2009-1373", "CVE-2009-1374", "CVE-2009-1375", "CVE-2009-1376");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200905-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200905-07
(Pidgin: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in Pidgin:
    Veracode reported a boundary error in the "XMPP SOCKS5 bytestream
    server" when initiating an outgoing file transfer (CVE-2009-1373).
    Ka-Hing Cheung reported a heap corruption flaw in the QQ protocol
    handler (CVE-2009-1374).
    A memory corruption flaw in
    "PurpleCircBuffer" was disclosed by Josef Andrysek
    (CVE-2009-1375).
    The previous fix for CVE-2008-2927 contains a
    cast from uint64 to size_t, possibly leading to an integer overflow
    (CVE-2009-1376, GLSA 200901-13).
  
Impact

    A remote attacker could send specially crafted messages or files using
    the MSN, XMPP or QQ protocols, possibly resulting in the execution of
    arbitrary code with the privileges of the user running the application,
    or a Denial of Service. NOTE: Successful exploitation might require the
    victim\'s interaction.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pidgin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/pidgin-2.5.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1373');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1374');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1375');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1376');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-13.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200905-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200905-07] Pidgin: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pidgin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/pidgin", unaffected: make_list("ge 2.5.6"), vulnerable: make_list("lt 2.5.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
