# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-14.xml
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
 script_id(26104);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200709-14");
 script_cve_id("CVE-2007-4510", "CVE-2007-4560");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-14
(ClamAV: Multiple vulnerabilities)


    Nikolaos Rangos discovered a vulnerability in ClamAV which exists
    because the recipient address extracted from email messages is not
    properly sanitized before being used in a call to "popen()" when
    executing sendmail (CVE-2007-4560). Also, NULL-pointer dereference
    errors exist within the "cli_scanrtf()" function in libclamav/rtf.c and
    Stefanos Stamatis discovered a NULL-pointer dereference vulnerability
    within the "cli_html_normalise()" function in libclamav/htmlnorm.c
    (CVE-2007-4510).
  
Impact

    The unsanitized recipient address can be exploited to execute arbitrary
    code with the privileges of the clamav-milter process by sending an
    email with a specially crafted recipient address to the affected
    system. Also, the NULL-pointer dereference errors can be exploited to
    crash ClamAV. Successful exploitation of the latter vulnerability
    requires that clamav-milter is started with the "black hole" mode
    activated, which is not enabled by default.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.91.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4510');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4560');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-14] ClamAV: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.91.2"), vulnerable: make_list("lt 0.91.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
