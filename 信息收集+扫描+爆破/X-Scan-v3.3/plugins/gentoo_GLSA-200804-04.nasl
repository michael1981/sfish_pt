# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-04.xml
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
 script_id(31835);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200804-04");
 script_cve_id("CVE-2007-5969", "CVE-2007-6303", "CVE-2007-6304");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-04
(MySQL: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in MySQL:
    Mattias Jonsson reported that a "RENAME TABLE" command against a
    table with explicit "DATA DIRECTORY" and "INDEX DIRECTORY" options
    would overwrite the file to which the symlink points
    (CVE-2007-5969).
    Martin Friebe discovered that MySQL does not
    update the DEFINER value of a view when the view is altered
    (CVE-2007-6303).
    Philip Stoev discovered that the federated
    engine expects the response of a remote MySQL server to contain a
    minimum number of columns in query replies (CVE-2007-6304).
  
Impact

    An authenticated remote attacker could exploit the first vulnerability
    to overwrite MySQL system tables and escalate privileges, or use the
    second vulnerability to gain privileges via an "ALTER VIEW" statement.
    Remote federated MySQL servers could cause a Denial of Service in the
    local MySQL server by exploiting the third vulnerability.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MySQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/mysql-5.0.54"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5969');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6303');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6304');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-04] MySQL: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 5.0.54"), vulnerable: make_list("lt 5.0.54")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
