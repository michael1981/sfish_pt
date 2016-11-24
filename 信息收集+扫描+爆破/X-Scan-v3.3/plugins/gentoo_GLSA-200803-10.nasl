# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-10.xml
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
 script_id(31385);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200803-10");
 script_cve_id("CVE-2008-0983", "CVE-2008-1111");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-10
(lighttpd: Multiple vulnerabilities)


    lighttpd contains a calculation error when allocating the global file
    descriptor array (CVE-2008-0983). Furthermore, it sends the source of a
    CGI script instead of returning a 500 error (Internal Server Error)
    when the fork() system call fails (CVE-2008-1111).
  
Impact

    A remote attacker could exploit these vulnerabilities to cause a Denial
    of Service or gain the source of a CGI script.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All lighttpd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/lighttpd-1.4.18-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0983');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1111');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-10] lighttpd: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'lighttpd: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/lighttpd", unaffected: make_list("ge 1.4.18-r2"), vulnerable: make_list("lt 1.4.18-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
