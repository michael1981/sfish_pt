# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-10.xml
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
 script_id(14566);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200408-10");
 script_cve_id("CVE-2002-0838");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-10
(gv: Exploitable Buffer Overflow)


    gv contains a buffer overflow vulnerability where an unsafe sscanf() call
    is used to interpret PDF and PostScript files.
  
Impact

    By enticing a user to view a malformed PDF or PostScript file an attacker
    could execute arbitrary code with the permissions of the user running gv.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of gv.
  
');
script_set_attribute(attribute:'solution', value: '
    All gv users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-text/gv-3.5.8-r4"
    # emerge ">=app-text/gv-3.5.8-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2002-0838');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-10] gv: Exploitable Buffer Overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gv: Exploitable Buffer Overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/gv", unaffected: make_list("ge 3.5.8-r4"), vulnerable: make_list("le 3.5.8-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
