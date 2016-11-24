# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-11.xml
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
 script_id(14462);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200403-11");
 script_cve_id("CVE-2004-0189");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-11
(Squid ACL [url_regex] bypass vulnerability)


    A bug in Squid allows users to bypass certain access controls by passing a
    URL containing "%00" which exploits the Squid decoding function.
    This may insert a NUL character into decoded URLs, which may allow users to
    bypass url_regex access control lists that are enforced upon them.
    In such a scenario, Squid will insert a NUL character after
    the"%00" and it will make a comparison between the URL to the end
    of the NUL character rather than the contents after it: the comparison does
    not result in a match, and the user\'s request is not denied.
  
Impact

    Restricted users may be able to bypass url_regex access control lists that
    are enforced upon them which may cause unwanted network traffic as well as
    a route for other possible exploits. Users of Squid 2.5STABLE4 and below
    who require the url_regex features are recommended to upgrade to 2.5STABLE5
    to maintain the security of their infrastructure.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of Squid.
  
');
script_set_attribute(attribute:'solution', value: '
    Squid can be updated as follows:
    # emerge sync
    # emerge -pv ">=net-proxy/squid-2.5.5"
    # emerge ">=net-proxy/squid-2.5.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0189');
script_set_attribute(attribute: 'see_also', value: 'http://www.squid-cache.org/Advisories/SQUID-2004_1.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-11] Squid ACL [url_regex] bypass vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid ACL [url_regex] bypass vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/squid", unaffected: make_list("ge 2.5.5"), vulnerable: make_list("lt 2.5.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
