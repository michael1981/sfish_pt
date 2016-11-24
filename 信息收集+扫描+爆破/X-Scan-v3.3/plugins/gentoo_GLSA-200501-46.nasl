# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-46.xml
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
 script_id(16437);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-46");
 script_cve_id("CVE-2005-0133", "CVE-2005-0218");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-46 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-46
(ClamAV: Multiple issues)


    ClamAV fails to properly scan ZIP files with special headers
    (CAN-2005-0133) and base64 encoded images in URLs.
  
Impact

    By sending a base64 encoded image file in a URL an attacker could evade
    virus scanning. By sending a specially-crafted ZIP file an attacker
    could cause a Denial of Service by crashing the clamd daemon.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.81"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0133');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0218');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/forum/forum.php?forum_id=440649');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/13900/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-46.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-46] ClamAV: Multiple issues');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple issues');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.81"), vulnerable: make_list("le 0.80")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
