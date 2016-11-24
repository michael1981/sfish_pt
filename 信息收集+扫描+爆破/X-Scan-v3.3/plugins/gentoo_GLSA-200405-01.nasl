# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-01.xml
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
 script_id(14487);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-01");
 script_cve_id("CVE-2004-0179");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-01
(Multiple format string vulnerabilities in neon 0.24.4 and earlier)


    There are multiple format string vulnerabilities in libneon which may allow
    a malicious WebDAV server to execute arbitrary code under the context of
    the process using libneon.
  
Impact

    An attacker may be able to execute arbitrary code under the context of the
    process using libneon.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    Neon users should upgrade to version 0.24.5 or later:
    # emerge sync
    # emerge -pv ">=net-misc/neon-0.24.5"
    # emerge ">=net-misc/neon-0.24.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0179');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-01] Multiple format string vulnerabilities in neon 0.24.4 and earlier');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple format string vulnerabilities in neon 0.24.4 and earlier');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/neon", unaffected: make_list("ge 0.24.5"), vulnerable: make_list("le 0.24.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
