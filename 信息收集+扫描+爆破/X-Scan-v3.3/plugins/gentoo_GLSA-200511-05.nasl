# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-05.xml
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
 script_id(20155);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200511-05");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-05
(GNUMP3d: Directory traversal and XSS vulnerabilities)


    Steve Kemp reported about two cross-site scripting attacks that are
    related to the handling of files (CVE-2005-3424, CVE-2005-3425). Also
    reported is a directory traversal vulnerability which comes from the
    attempt to sanitize input paths (CVE-2005-3123).
  
Impact

    A remote attacker could exploit this to disclose sensitive information
    or inject and execute malicious script code, potentially compromising
    the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GNUMP3d users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/gnump3d-2.9_pre7"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3123');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3424');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3425');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-05] GNUMP3d: Directory traversal and XSS vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNUMP3d: Directory traversal and XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/gnump3d", unaffected: make_list("ge 2.9_pre7"), vulnerable: make_list("lt 2.9_pre7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
