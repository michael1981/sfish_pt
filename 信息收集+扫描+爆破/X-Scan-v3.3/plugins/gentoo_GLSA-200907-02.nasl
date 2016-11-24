# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200907-02.xml
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
 script_id(39596);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200907-02");
 script_cve_id("CVE-2009-1902", "CVE-2009-1903");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200907-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200907-02
(ModSecurity: Denial of Service)


    Multiple vulnerabilities were discovered in ModSecurity:
    Juan Galiana Lara of ISecAuditors discovered a NULL pointer
    dereference when processing multipart requests without a part header
    name (CVE-2009-1902).
    Steve Grubb of Red Hat reported that the
    "PDF XSS protection" feature does not properly handle HTTP requests to
    a PDF file that do not use the GET method (CVE-2009-1903).
  
Impact

    A remote attacker might send requests containing specially crafted
    multipart data or send certain requests to access a PDF file, possibly
    resulting in a Denial of Service (crash) of the Apache HTTP daemon.
    NOTE: The PDF XSS protection is not enabled by default.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ModSecurity users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apache/mod_security-2.5.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1902');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1903');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200907-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200907-02] ModSecurity: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ModSecurity: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apache/mod_security", unaffected: make_list("ge 2.5.9"), vulnerable: make_list("lt 2.5.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
