# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-24.xml
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
 script_id(24929);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200703-24");
 script_cve_id("CVE-2006-5864");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-24
(mgv: Stack overflow in included gv code)


    mgv includes code from gv that does not properly boundary check
    user-supplied data before copying it into process buffers.
  
Impact

    An attacker could entice a user to open a specially crafted Postscript
    document with mgv and possibly execute arbitrary code with the rights
    of the user running mgv.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    mgv is currently unmaintained, and the mgv website no longer exists. As
    such, the mgv package has been masked in Portage. We recommend that
    users select an alternate Postscript viewer such as ghostview or
    GSview, and unmerge mgv:
    # emerge --unmerge "app-text/mgv"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5864');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-20.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-24] mgv: Stack overflow in included gv code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mgv: Stack overflow in included gv code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/mgv", unaffected: make_list(), vulnerable: make_list("le 3.1.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
