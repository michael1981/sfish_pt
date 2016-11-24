# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-06.xml
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
 script_id(19439);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200508-06");
 script_cve_id("CVE-2005-2102", "CVE-2005-2103");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200508-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200508-06
(Gaim: Remote execution of arbitrary code)


    Brandon Perry discovered that Gaim is vulnerable to a heap-based
    buffer overflow when handling away messages (CAN-2005-2103).
    Furthermore, Daniel Atallah discovered a vulnerability in the handling
    of file transfers (CAN-2005-2102).
  
Impact

    A remote attacker could create a specially crafted away message
    which, when viewed by the target user, could lead to the execution of
    arbitrary code. Also, an attacker could send a file with a non-UTF8
    filename to a user, which would result in a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Gaim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/gaim-1.5.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2102');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2103');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200508-06] Gaim: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 1.5.0"), vulnerable: make_list("lt 1.5.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
