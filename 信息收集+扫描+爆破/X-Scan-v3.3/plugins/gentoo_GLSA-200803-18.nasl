# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-18.xml
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
 script_id(31444);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200803-18");
 script_cve_id("CVE-2008-0783", "CVE-2008-0784", "CVE-2008-0785", "CVE-2008-0786");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-18
(Cacti: Multiple vulnerabilities)


    The following inputs are not properly sanitized before being processed:
    "view_type" parameter in the file graph.php, "filter" parameter
    in the file graph_view.php, "action" and "login_username" parameters in
    the file index.php (CVE-2008-0783).
    "local_graph_id" parameter in the file graph.php
    (CVE-2008-0784).
    "graph_list" parameter in the file graph_view.php, "leaf_id" and
    "id" parameters in the file tree.php, "local_graph_id" in the file
    graph_xport.php (CVE-2008-0785).
    Furthermore, CRLF injection attack are possible via unspecified vectors
    (CVE-2008-0786).
  
Impact

    A remote attacker could exploit these vulnerabilities, leading to path
    disclosure, Cross-Site Scripting attacks, SQL injection, and HTTP
    response splitting.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Cacti users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/cacti-0.8.7b"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0783');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0784');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0785');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0786');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-18] Cacti: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cacti: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/cacti", unaffected: make_list("ge 0.8.7b", "rge 0.8.6j-r8"), vulnerable: make_list("lt 0.8.7b")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
