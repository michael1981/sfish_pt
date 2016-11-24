# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-18.xml
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
 script_id(41022);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200909-18");
 script_cve_id("CVE-2009-2629");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-18
(nginx: Remote execution of arbitrary code)


    Chris Ries reported a heap-based buffer underflow in the
    ngx_http_parse_complex_uri() function in http/ngx_http_parse.c when
    parsing the request URI.
  
Impact

    A remote attacker might send a specially crafted request URI to a nginx
    server, possibly resulting in the remote execution of arbitrary code
    with the privileges of the user running the server, or a Denial of
    Service. NOTE: By default, nginx runs as the "nginx" user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All nginx 0.5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-servers/nginx-0.5.38
    All nginx 0.6.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-servers/nginx-0.6.39
    All nginx 0.7.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-servers/nginx-0.7.62
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2629');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-18] nginx: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'nginx: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/nginx", unaffected: make_list("rge 0.5.38", "rge 0.6.39", "ge 0.7.62"), vulnerable: make_list("lt 0.7.62")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
