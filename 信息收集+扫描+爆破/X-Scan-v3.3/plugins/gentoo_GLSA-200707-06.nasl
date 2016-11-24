# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200707-06.xml
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
 script_id(25719);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200707-06");
 script_cve_id("CVE-2007-2194");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200707-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200707-06
(XnView: Stack-based buffer overflow)


    XnView is vulnerable to a stack-based buffer overflow while processing
    an XPM file with an overly long section string (greater than 1024
    bytes).
  
Impact

    An attacker could entice a user to view a specially crafted XPM file
    with XnView that could trigger the vulnerability and possibly execute
    arbitrary code with the rights of the user running XnView.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    No update appears to be forthcoming from the XnView developer and
    XnView is proprietary, so the XnView package has been masked in
    Portage. We recommend that users select an alternate graphics viewer
    and conversion utility, and unmerge XnView:
    # emerge --unmerge xnview
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2194');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200707-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200707-06] XnView: Stack-based buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XnView: Stack-based buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-misc/xnview", arch: "x86", unaffected: make_list(), vulnerable: make_list("lt 1.70")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
