# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-05.xml
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
 script_id(21666);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200606-05");
 script_cve_id("CVE-2005-3751");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-05
(Pound: HTTP request smuggling)


    Pound fails to handle HTTP requests with conflicting "Content-Length"
    and "Transfer-Encoding" headers correctly.
  
Impact

    An attacker could exploit this vulnerability by sending HTTP requests
    with specially crafted "Content-Length" and "Transfer-Encoding" headers
    to bypass certain security restrictions or to poison the web proxy
    cache.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pound users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose www-servers/pound
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3751');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-05] Pound: HTTP request smuggling');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pound: HTTP request smuggling');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/pound", unaffected: make_list("ge 2.0.5", "rge 1.10", "rge 1.9.4"), vulnerable: make_list("lt 2.0.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
