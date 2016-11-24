# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-04.xml
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
 script_id(17251);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200503-04");
 script_cve_id("CVE-2005-0565", "CVE-2005-0572");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-04
(phpWebSite: Arbitrary PHP execution and path disclosure)


    NST discovered that, when submitting an announcement, uploaded files
    aren\'t correctly checked for malicious code. They also found out that
    phpWebSite is vulnerable to a path disclosure.
  
Impact

    A remote attacker can exploit this issue to upload files to a directory
    within the web root. By calling the uploaded script the attacker could
    then execute arbitrary PHP code with the rights of the web server. By
    passing specially crafted requests to the search module, remote
    attackers can also find out the full path of PHP scripts.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpWebSite users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpwebsite-0.10.0-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/14399/');
script_set_attribute(attribute: 'see_also', value: 'http://phpwebsite.appstate.edu/index.php?module=announce&ANN_id=922&ANN_user_op=view');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0565');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0572');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-04] phpWebSite: Arbitrary PHP execution and path disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpWebSite: Arbitrary PHP execution and path disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpwebsite", unaffected: make_list("ge 0.10.0-r2"), vulnerable: make_list("lt 0.10.0-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
