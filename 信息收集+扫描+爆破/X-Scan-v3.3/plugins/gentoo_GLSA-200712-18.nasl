# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-18.xml
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
 script_id(29815);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200712-18");
 script_cve_id("CVE-2007-5824", "CVE-2007-5825");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-18
(Multi-Threaded DAAP Daemon: Multiple vulnerabilities)


    nnp discovered multiple vulnerabilities in the XML-RPC handler in the
    file webserver.c. The ws_addarg() function contains a format string
    vulnerability, as it does not properly sanitize username and password
    data from the "Authorization: Basic" HTTP header line (CVE-2007-5825).
    The ws_decodepassword() and ws_getheaders() functions do not correctly
    handle empty Authorization header lines, or header lines without a \':\'
    character, leading to NULL pointer dereferences (CVE-2007-5824).
  
Impact

    A remote attacker could send specially crafted HTTP requests to the web
    server in the Multi-Threaded DAAP Daemon, possibly leading to the
    execution of arbitrary code with the privileges of the user running the
    web server or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Multi-Threaded DAAP Daemon users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/mt-daapd-0.2.4.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5824');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5825');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-18] Multi-Threaded DAAP Daemon: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multi-Threaded DAAP Daemon: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/mt-daapd", unaffected: make_list("ge 0.2.4.1"), vulnerable: make_list("lt 0.2.4.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
