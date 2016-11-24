# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-12.xml
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
 script_id(24210);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200701-12");
 script_cve_id("CVE-2006-6104");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-12
(Mono: Information disclosure)


    Jose Ramon Palanco has discovered that the System.Web class in the XSP
    for the ASP.NET server 1.1 through 2.0 in Mono does not properly
    validate or sanitize local pathnames which could allow server-side file
    content disclosure.
  
Impact

    An attacker could append a space character to a URI and obtain
    unauthorized access to the source code of server-side files. An
    attacker could also read credentials by requesting Web.Config%20 from a
    Mono server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mono users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/mono-1.2.2.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6104');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-12] Mono: Information disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mono: Information disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/mono", unaffected: make_list("ge 1.2.2.1"), vulnerable: make_list("lt 1.2.2.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
