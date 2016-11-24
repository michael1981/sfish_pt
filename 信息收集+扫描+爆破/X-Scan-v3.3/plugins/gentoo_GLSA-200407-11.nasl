# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-11.xml
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
 script_id(14544);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-11");
 script_cve_id("CVE-2004-0645");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-11
(wv: Buffer overflow vulnerability)


    A use of strcat without proper bounds checking leads to an exploitable
    buffer overflow. The vulnerable code is executed when wv encounters an
    unrecognized token, so a specially crafted file, loaded in wv, can
    trigger the vulnerable code and execute it\'s own arbitrary code. This
    exploit is only possible when the user loads the document into HTML
    view mode.
  
Impact

    By inducing a user into running wv on a special file, an attacker can
    execute arbitrary code with the permissions of the user running the
    vulnerable program.
  
Workaround

    Users should not view untrusted documents with wvHtml or applications
    using wv. When loading an untrusted document in an application using
    the wv library, make sure HTML view is disabled.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest available version.
    # emerge sync
    # emerge -pv ">=app-text/wv-1.0.0-r1"
    # emerge ">=app-text/wv-1.0.0-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=115&type=vulnerabilities&flashstatus=true');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0645');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-11] wv: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'wv: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/wv", unaffected: make_list("ge 1.0.0-r1"), vulnerable: make_list("lt 1.0.0-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
