# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-06.xml
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
 script_id(14539);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200407-06");
 script_cve_id("CVE-2002-1363");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-06
(libpng: Buffer overflow on row buffers)


    Due to a wrong calculation of loop offset values, libpng contains a buffer
    overflow vulnerability on the row buffers. This vulnerability was initially
    patched in January 2003 but since it has been discovered that libpng
    contains the same vulnerability in two other places.
  
Impact

    An attacker could exploit this vulnerability to cause programs linked
    against the library to crash or execute arbitrary code with the permissions
    of the user running the vulnerable program, which could be the root user.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All libpng users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=media-libs/libpng-1.2.5-r7"
    # emerge ">=media-libs/libpng-1.2.5-r7"
    You should also run revdep-rebuild to rebuild any packages that depend on
    older versions of libpng :
    # revdep-rebuild
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2002-1363');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-06] libpng: Buffer overflow on row buffers');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libpng: Buffer overflow on row buffers');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libpng", unaffected: make_list("ge 1.2.5-r7"), vulnerable: make_list("le 1.2.5-r6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
