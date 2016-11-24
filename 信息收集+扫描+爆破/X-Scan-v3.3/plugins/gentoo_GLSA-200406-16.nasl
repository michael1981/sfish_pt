# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-16.xml
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
 script_id(14527);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200406-16");
 script_cve_id("CVE-2004-0492");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-16
(Apache 1.3: Buffer overflow in mod_proxy)


    A bug in the proxy_util.c file may lead to a remote buffer overflow. To
    trigger the vulnerability an attacker would have to get mod_proxy to
    connect to a malicous server which returns an invalid (negative)
    Content-Length.
  
Impact

    An attacker could cause a Denial of Service as the Apache child handling
    the request, which will die and under some circumstances execute arbitrary
    code as the user running Apache, usually "apache".
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version:
  
');
script_set_attribute(attribute:'solution', value: '
    Apache 1.x users should upgrade to the latest version of Apache:
    # emerge sync
    # emerge -pv ">=www-servers/apache-1.3.31-r2"
    # emerge ">=www-servers/apache-1.3.31-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.guninski.com/modproxy1.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0492');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-16] Apache 1.3: Buffer overflow in mod_proxy');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 1.3: Buffer overflow in mod_proxy');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 1.3.31-r2"), vulnerable: make_list("le 1.3.31-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
