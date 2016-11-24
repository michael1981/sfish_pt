# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-14.xml
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
 script_id(14479);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200404-14");
 script_cve_id("CVE-2004-0179");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-14
(Multiple format string vulnerabilities in cadaver)


    Cadaver code includes the neon library, which in versions 0.24.4 and
    previous is vulnerable to multiple format string attacks. The latest
    version of cadaver uses version 0.24.5 of the neon library, which makes it
    immune to this vulnerability.
  
Impact

    When using cadaver to connect to an untrusted WebDAV server, this
    vulnerability can allow a malicious remote server to execute arbitrary code
    on the client with the rights of the user using cadaver.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    cadaver users should upgrade to version 0.22.1 or later:
    # emerge sync
    # emerge -pv ">=net-misc/cadaver-0.22.1"
    # emerge ">=net-misc/cadaver-0.22.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.webdav.org/cadaver');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0179');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-14] Multiple format string vulnerabilities in cadaver');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple format string vulnerabilities in cadaver');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/cadaver", unaffected: make_list("ge 0.22.1"), vulnerable: make_list("lt 0.22.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
