# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-14.xml
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
 script_id(35102);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200812-14");
 script_cve_id("CVE-2008-4935");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-14
(aview: Insecure temporary file usage)


    Dmitry E. Oboukhov reported that aview uses the "/tmp/aview$$.pgm" file
    in an insecure manner when processing files.
  
Impact

    A local attacker could perform symlink attacks to overwrite arbitrary
    files on the system with the privileges of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All aview users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/aview-1.3.0_rc1-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4935');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-14] aview: Insecure temporary file usage');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'aview: Insecure temporary file usage');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/aview", unaffected: make_list("ge 1.3.0_rc1-r1"), vulnerable: make_list("lt 1.3.0_rc1-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
