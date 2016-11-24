# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-23.xml
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
 script_id(16034);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200412-23");
 script_cve_id("CVE-2004-1075");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-23
(Zwiki: XSS vulnerability)


    Due to improper input validation, Zwiki can be exploited to perform
    cross-site scripting attacks.
  
Impact

    By enticing a user to read a specially-crafted wiki entry, an attacker
    can execute arbitrary script code running in the context of the
    victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Zwiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-zope/zwiki-0.36.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://zwiki.org/925ZwikiXSSVulnerability');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1075');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-23] Zwiki: XSS vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Zwiki: XSS vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-zope/zwiki", unaffected: make_list("ge 0.36.2-r1"), vulnerable: make_list("lt 0.36.2-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
