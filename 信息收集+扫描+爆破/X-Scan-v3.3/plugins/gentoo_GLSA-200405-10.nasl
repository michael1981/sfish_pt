# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-10.xml
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
 script_id(14496);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200405-10");
 script_cve_id("CVE-2004-2027");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-10
(Icecast denial of service vulnerability)


    There is an out-of-bounds read error in the web interface of Icecast
    when handling Basic Authorization requests. This vulnerability can
    theorically be exploited by sending a specially crafted Authorization
    header to the server.
  
Impact

    By exploiting this vulnerability, it is possible to crash the Icecast
    server remotely, resulting in a denial of service attack.
  
Workaround

    There is no known workaround at this time. All users are advised to
    upgrade to the latest available version of Icecast.
  
');
script_set_attribute(attribute:'solution', value: '
    All users of Icecast should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-misc/icecast-2.0.1"
    # emerge ">=net-misc/icecast-2.0.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.xiph.org/archives/icecast/7144.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2027');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-10] Icecast denial of service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Icecast denial of service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/icecast", unaffected: make_list("ge 2.0.1"), vulnerable: make_list("le 2.0.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
