# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-19.xml
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
 script_id(17344);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200503-19");
 script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-19
(MySQL: Multiple vulnerabilities)


    MySQL fails to properly validate input for authenticated users with
    INSERT and DELETE privileges (CAN-2005-0709 and CAN-2005-0710).
    Furthermore MySQL uses predictable filenames when creating temporary
    files with CREATE TEMPORARY TABLE (CAN-2005-0711).
  
Impact

    An attacker with INSERT and DELETE privileges could exploit this to
    manipulate the mysql table or accessing libc calls, potentially leading
    to the execution of arbitrary code with the permissions of the user
    running MySQL. An attacker with CREATE TEMPORARY TABLE privileges could
    exploit this to overwrite arbitrary files via a symlink attack.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MySQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/mysql-4.0.24"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0709');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0710');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0711');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-19] MySQL: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 4.0.24"), vulnerable: make_list("lt 4.0.24")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
