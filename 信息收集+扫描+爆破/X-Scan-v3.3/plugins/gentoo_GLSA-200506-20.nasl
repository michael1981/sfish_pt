# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-20.xml
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
 script_id(18547);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200506-20");
 script_cve_id("CVE-2005-1524", "CVE-2005-1525", "CVE-2005-1526");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-20
(Cacti: Several vulnerabilities)


    Cacti fails to properly sanitize input which can lead to SQL injection,
    authentication bypass as well as PHP file inclusion.
  
Impact

    An attacker could potentially exploit the file inclusion to execute
    arbitrary code with the permissions of the web server. An attacker
    could exploit these vulnerabilities to bypass authentication or inject
    SQL queries to gain information from the database. Only systems with
    register_globals set to "On" are affected by the file inclusion and
    authentication bypass vulnerabilities. Gentoo Linux ships with
    register_globals set to "Off" by default.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Cacti users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/cacti-0.8.6f"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.cacti.net/release_notes_0_8_6e.php');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=267&type=vulnerabilities&flashstatus=false');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=266&type=vulnerabilities&flashstatus=false');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=265&type=vulnerabilities&flashstatus=false');
script_set_attribute(attribute: 'see_also', value: 'http://www.cacti.net/release_notes_0_8_6f.php');
script_set_attribute(attribute: 'see_also', value: 'http://www.hardened-php.net/advisory-032005.php');
script_set_attribute(attribute: 'see_also', value: 'http://www.hardened-php.net/advisory-042005.php');
script_set_attribute(attribute: 'see_also', value: 'http://www.hardened-php.net/advisory-052005.php');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1524');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1525');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1526');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-20] Cacti: Several vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cacti: Several vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/cacti", unaffected: make_list("ge 0.8.6f"), vulnerable: make_list("lt 0.8.6f")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
