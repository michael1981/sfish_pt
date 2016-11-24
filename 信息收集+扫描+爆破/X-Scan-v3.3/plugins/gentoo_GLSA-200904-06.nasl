# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-06.xml
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
 script_id(36094);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200904-06");
 script_cve_id("CVE-2008-5983", "CVE-2008-5987");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-06
(Eye of GNOME: Untrusted search path)


    James Vega reported an untrusted search path vulnerability in the
    GObject Python interpreter wrapper in the Eye of GNOME, a vulnerabiliy
    related to CVE-2008-5983.
  
Impact

    A local attacker could entice a user to run the Eye of GNOME from a
    directory containing a specially crafted python module, resulting in
    the execution of arbitrary code with the privileges of the user running
    the application.
  
Workaround

    Do not run "eog" from untrusted working directories.
  
');
script_set_attribute(attribute:'solution', value: '
    All Eye of GNOME users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/eog-2.22.3-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5983');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5987');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-06] Eye of GNOME: Untrusted search path');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Eye of GNOME: Untrusted search path');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/eog", unaffected: make_list("ge 2.22.3-r3"), vulnerable: make_list("lt 2.22.3-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
