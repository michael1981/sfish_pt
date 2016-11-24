# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-06.xml
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
 script_id(27823);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-06");
 script_cve_id("CVE-2006-5752", "CVE-2007-1862", "CVE-2007-1863", "CVE-2007-3304", "CVE-2007-3847", "CVE-2007-4465");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-06
(Apache: Multiple vulnerabilities)


    Multiple cross-site scripting vulnerabilities have been discovered in
    mod_status and mod_autoindex (CVE-2006-5752, CVE-2007-4465). An error
    has been discovered in the recall_headers() function in mod_mem_cache
    (CVE-2007-1862). The mod_cache module does not properly sanitize
    requests before processing them (CVE-2007-1863). The Prefork module
    does not properly check PID values before sending signals
    (CVE-2007-3304). The mod_proxy module does not correctly check headers
    before processing them (CVE-2007-3847).
  
Impact

    A remote attacker could exploit one of these vulnerabilities to inject
    arbitrary script or HTML content, obtain sensitive information or cause
    a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/apache-2.0.59-r5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5752');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1862');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1863');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3304');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3847');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4465');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-06] Apache: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("rge 2.0.59-r5", "ge 2.2.6"), vulnerable: make_list("lt 2.2.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
