# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-40.xml
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
 script_id(36048);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200903-40");
 script_cve_id("CVE-2008-1372");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-40 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-40
(Analog: Denial of Service)


    Diego E. Petteno reported that the Analog package in Gentoo is built
    with its own copy of bzip2, making it vulnerable to CVE-2008-1372 (GLSA
    200804-02).
  
Impact

    A local attacker could place specially crafted log files into a log
    directory being analyzed by analog, e.g. /var/log/apache, resulting in
    a crash when being processed by the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Analog users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/analog-6.0-r2"
    NOTE: Analog is now linked against the system bzip2 library.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1372');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-02.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-40.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-40] Analog: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Analog: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/analog", unaffected: make_list("ge 6.0-r2"), vulnerable: make_list("lt 6.0-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
