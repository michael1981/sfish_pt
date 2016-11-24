# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-26.xml
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
 script_id(16068);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200412-26");
 script_cve_id("CVE-2004-0915", "CVE-2004-1062");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-26
(ViewCVS: Information leak and XSS vulnerabilities)


    The tar export functions in ViewCVS bypass the \'hide_cvsroot\' and
    \'forbidden\' settings and therefore expose information that should be
    kept secret (CAN-2004-0915). Furthermore, some error messages in
    ViewCVS do not filter user-provided information, making it vulnerable
    to a cross-site scripting attack (CAN-2004-1062).
  
Impact

    By using the tar export functions, a remote attacker could access
    information that is configured as restricted. Through the use of a
    malicious request, an attacker could also inject and execute malicious
    script code, potentially compromising another user\'s browser.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ViewCVS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/viewcvs-0.9.2_p20041207-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0915');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1062');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-26] ViewCVS: Information leak and XSS vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ViewCVS: Information leak and XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/viewcvs", unaffected: make_list("ge 0.9.2_p20041207-r1"), vulnerable: make_list("le 0.9.2_p20041207")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
