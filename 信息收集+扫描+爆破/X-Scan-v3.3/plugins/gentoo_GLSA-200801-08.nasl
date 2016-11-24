# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200801-08.xml
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
 script_id(30032);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200801-08");
 script_cve_id("CVE-2007-6613");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200801-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200801-08
(libcdio: User-assisted execution of arbitrary code)


    Devon Miller reported a boundary error in the "print_iso9660_recurse()"
    function in files cd-info.c and iso-info.c when processing long
    filenames within Joliet images.
  
Impact

    A remote attacker could entice a user to open a specially crafted ISO
    image in the cd-info and iso-info applications, resulting in the
    execution of arbitrary code with the privileges of the user running the
    application. Applications linking against shared libraries of libcdio
    are not affected.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libcdio users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/libcdio-0.78.2-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6613');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200801-08] libcdio: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libcdio: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/libcdio", unaffected: make_list("ge 0.78.2-r4"), vulnerable: make_list("lt 0.78.2-r4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
