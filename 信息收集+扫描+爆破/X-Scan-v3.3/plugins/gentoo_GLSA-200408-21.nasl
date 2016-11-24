# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-21.xml
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
 script_id(14577);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200408-21");
 script_cve_id("CVE-2004-1737");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-21
(Cacti: SQL injection vulnerability)


    Cacti is vulnerable to a SQL injection attack where an attacker may
    inject SQL into the Username field.
  
Impact

    An attacker could compromise the Cacti service and potentially execute
    programs with the permissions of the user running Cacti. Only systems
    with php_flag magic_quotes_gpc set to Off are vulnerable. By default,
    Gentoo Linux installs PHP with this option set to On.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Cacti.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest available version of Cacti, as
    follows:
    # emerge sync
    # emerge -pv ">=net-analyzer/cacti-0.8.5a-r1"
    # emerge ">=net-analyzer/cacti-0.8.5a-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0717.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1737');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-21] Cacti: SQL injection vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cacti: SQL injection vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/cacti", unaffected: make_list("ge 0.8.5a-r1"), vulnerable: make_list("le 0.8.5a")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
