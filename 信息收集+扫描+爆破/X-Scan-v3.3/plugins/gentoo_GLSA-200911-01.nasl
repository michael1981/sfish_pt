# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200911-01.xml
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
 script_id(42415);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200911-01");
 script_cve_id("CVE-2009-3236", "CVE-2009-3237");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200911-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200911-01
(Horde: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in Horde:
    Stefan Esser of Sektion1 reported an error within the form library
    when handling image form fields (CVE-2009-3236).
    Martin
    Geisler and David Wharton reported that an error exists in the MIME
    viewer library when viewing unknown text parts and the preferences
    system in services/prefs.php when handling number preferences
    (CVE-2009-3237).
  
Impact

    A remote authenticated attacker could exploit these vulnerabilities to
    overwrite arbitrary files on the server, provided that the user has
    write permissions. A remote authenticated attacker could conduct
    Cross-Site Scripting attacks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Horde users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-3.3.5
    All Horde webmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-webmail-1.2.4
    All Horde groupware users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-groupware-1.2.4
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3236');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3237');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200911-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200911-01] Horde: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/horde-webmail", unaffected: make_list("ge 1.2.4"), vulnerable: make_list("lt 1.2.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde", unaffected: make_list("ge 3.3.5"), vulnerable: make_list("lt 3.3.5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-apps/horde-groupware", unaffected: make_list("ge 1.2.4"), vulnerable: make_list("lt 1.2.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
