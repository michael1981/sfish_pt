# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-24.xml
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
 script_id(22286);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200608-24");
 script_cve_id("CVE-2006-4089");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-24
(AlsaPlayer: Multiple buffer overflows)


    AlsaPlayer contains three buffer overflows: in the function that
    handles the HTTP connections, the GTK interface, and the CDDB querying
    mechanism.
  
Impact

    An attacker could exploit the first vulnerability by enticing a user to
    load a malicious URL resulting in the execution of arbitrary code with
    the permissions of the user running AlsaPlayer.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    AlsaPlayer has been masked in Portage pending the resolution of these
    issues. AlsaPlayer users are advised to uninstall the package until
    further notice:
    # emerge --ask --unmerge "media-sound/alsaplayer"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=2006-4089');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-24] AlsaPlayer: Multiple buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AlsaPlayer: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/alsaplayer", unaffected: make_list(), vulnerable: make_list("le 0.99.76-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
