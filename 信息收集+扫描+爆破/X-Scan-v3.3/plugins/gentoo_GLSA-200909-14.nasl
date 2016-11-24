# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-14.xml
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
 script_id(40961);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200909-14");
 script_cve_id("CVE-2008-5917", "CVE-2009-0930", "CVE-2009-0931", "CVE-2009-0932", "CVE-2009-2360");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-14
(Horde: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in Horde:
    Gunnar Wrobel reported an input sanitation and directory traversal
    flaw in framework/Image/Image.php, related to the "Horde_Image driver
    name" (CVE-2009-0932).
    Gunnar Wrobel reported that data sent
    to horde/services/portal/cloud_search.php is not properly sanitized
    before used in the output (CVE-2009-0931).
    It was reported
    that data sent to framework/Text_Filter/Filter/xss.php is not properly
    sanitized before used in the output (CVE-2008-5917).
    Horde Passwd: David Wharton reported that data sent via the "backend"
    parameter to passwd/main.php is not properly sanitized before used in
    the output (CVE-2009-2360).
    Horde IMP: Gunnar Wrobel reported that data sent to smime.php, pgp.php,
    and message.php is not properly sanitized before used in the output
    (CVE-2009-0930).
  
Impact

    A remote authenticated attacker could exploit these vulnerabilities to
    execute arbitrary PHP files on the server, or disclose the content of
    arbitrary files, both only if the file is readable to the web server. A
    remote authenticated attacker could conduct Cross-Site Scripting
    attacks. NOTE: Some Cross-Site Scripting vectors are limited to the
    usage of Microsoft Internet Explorer.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Horde users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-3.3.4
    All Horde IMP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-imp-4.3.4
    All Horde Passwd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-passwd-3.1.1
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5917');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0930');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0931');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0932');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2360');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-14] Horde: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/horde-imp", unaffected: make_list("ge 4.3.4"), vulnerable: make_list("lt 4.3.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-passwd", unaffected: make_list("ge 3.1.1"), vulnerable: make_list("lt 3.1.1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde", unaffected: make_list("ge 3.3.4"), vulnerable: make_list("lt 3.3.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
