# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-29.xml
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
 script_id(19360);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200507-29");
 script_cve_id("CVE-2005-2536");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-29 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-29
(pstotext: Remote execution of arbitrary code)


    Max Vozeler reported that pstotext calls the GhostScript interpreter on
    untrusted PostScript files without specifying the -dSAFER option.
  
Impact

    An attacker could craft a malicious PostScript file and entice a user
    to run pstotext on it, resulting in the execution of arbitrary commands
    with the permissions of the user running pstotext.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All pstotext users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/pstotext-1.8g-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2536');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/16183/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-29.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-29] pstotext: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'pstotext: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/pstotext", unaffected: make_list("ge 1.8g-r1"), vulnerable: make_list("lt 1.8g-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
