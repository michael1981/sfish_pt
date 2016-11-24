# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-15.xml
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
 script_id(14501);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200405-15");
 script_cve_id("CVE-2004-0398");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-15
(cadaver heap-based buffer overflow)


    Stefan Esser discovered a vulnerability in the code of the neon library
    (see GLSA 200405-13). This library is also included in cadaver.
  
Impact

    When connected to a malicious WebDAV server, this vulnerability could allow
    remote execution of arbitrary code with the rights of the user running
    cadaver.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of cadaver.
  
');
script_set_attribute(attribute:'solution', value: '
    All users of cadaver should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-misc/cadaver-0.22.2"
    # emerge ">=net-misc/cadaver-0.22.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0398');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-13.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-15] cadaver heap-based buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cadaver heap-based buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/cadaver", unaffected: make_list("ge 0.22.2"), vulnerable: make_list("le 0.22.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
