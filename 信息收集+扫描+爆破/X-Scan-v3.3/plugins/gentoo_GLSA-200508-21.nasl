# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-21.xml
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
 script_id(19574);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200508-21");
 script_cve_id("CVE-2005-2498");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200508-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200508-21
(phpWebSite: Arbitrary command execution through XML-RPC and SQL injection)


    phpWebSite uses an XML-RPC library that improperly handles XML-RPC
    requests and responses with malformed nested tags. Furthermore,
    "matrix_killer" reported that phpWebSite is vulnerable to an SQL
    injection attack.
  
Impact

    A malicious remote user could exploit this vulnerability to inject
    arbitrary PHP script code into eval() statements by sending a specially
    crafted XML document, and also inject SQL commands to access the
    underlying database directly.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpWebSite users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpwebsite-0.10.2_rc2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2498');
script_set_attribute(attribute: 'see_also', value: 'http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0497.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200508-21] phpWebSite: Arbitrary command execution through XML-RPC and SQL injection');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpWebSite: Arbitrary command execution through XML-RPC and SQL injection');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpwebsite", unaffected: make_list("ge 0.10.2_rc2"), vulnerable: make_list("lt 0.10.2_rc2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
