# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-13.xml
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
 script_id(27848);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-13");
 script_cve_id("CVE-2007-5622");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-13
(3proxy: Denial of Service)


    3proxy contains a double free vulnerability in the ftpprchild()
    function, which frees param->hostname and calls the parsehostname()
    function, which in turn attempts to free param->hostname again.
  
Impact

    A remote attacker could send a specially crafted request to the proxy,
    possibly resulting in a Denial of Service. Under typical configuration,
    the scope of this vulnerability is limited to the local network.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All 3proxy users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-proxy/3proxy-0.5.3j"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5622');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-13] 3proxy: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: '3proxy: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/3proxy", unaffected: make_list("ge 0.5.3j"), vulnerable: make_list("lt 0.5.3j")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
