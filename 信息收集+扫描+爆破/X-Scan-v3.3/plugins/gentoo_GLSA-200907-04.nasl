# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200907-04.xml
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
 script_id(39775);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200907-04");
 script_cve_id("CVE-2009-1195", "CVE-2009-1191", "CVE-2009-1890", "CVE-2009-1891");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200907-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200907-04
(Apache: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in the Apache HTTP
    server:
    Jonathan Peatfield reported that the
    "Options=IncludesNoEXEC" argument to the "AllowOverride" directive is
    not processed properly (CVE-2009-1195).
    Sander de Boer
    discovered that the AJP proxy module (mod_proxy_ajp) does not correctly
    handle POST requests that do not contain a request body
    (CVE-2009-1191).
    The vendor reported that the HTTP proxy
    module (mod_proxy_http), when being used as a reverse proxy, does not
    properly handle requests containing more data as stated in the
    "Content-Length" header (CVE-2009-1890).
    Francois Guerraz
    discovered that mod_deflate does not abort the compression of large
    files even when the requesting connection is closed prematurely
    (CVE-2009-1891).
  
Impact

    A local attacker could circumvent restrictions put up by the server
    administrator and execute arbitrary commands with the privileges of the
    user running the Apache server. A remote attacker could send multiple
    requests to a server with the AJP proxy module, possibly resulting in
    the disclosure of a request intended for another client, or cause a
    Denial of Service by sending specially crafted requests to servers
    running mod_proxy_http or mod_deflate.
  
Workaround

    Remove "include", "proxy_ajp", "proxy_http" and "deflate" from
    APACHE2_MODULES in make.conf and rebuild Apache, or disable the
    aforementioned modules in the Apache configuration.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/apache-2.2.11-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1195');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1191');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1890');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1891');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200907-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200907-04] Apache: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 2.2.11-r2"), vulnerable: make_list("lt 2.2.11-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
